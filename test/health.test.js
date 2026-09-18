import test from "node:test";
import assert from "node:assert/strict";
import {spawn} from "node:child_process";

const port = 3300 + Math.floor(Math.random() * 500);
const loopback = [127, 0, 0, 1].join(".");
const baseUrl = `http://${loopback}:${port}`;

function startServer() {
  const child = spawn(process.execPath, ["server.js"], {
    cwd: new URL("..", import.meta.url),
    env: {...process.env, PORT:String(port), FRONTEND_URL:baseUrl, DATABASE_URL:""},
    stdio:["ignore", "pipe", "pipe"]
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", chunk => { stderr += chunk; });
  child.startupError = () => stderr.trim();
  return child;
}

async function waitForHealth(server) {
  for (let attempt = 0; attempt < 30; attempt++) {
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) return;
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  const startupError = server.startupError();
  throw new Error(`Server did not become healthy.${startupError ? ` ${startupError}` : ""}`);
}

test("health and config expose safe operational contracts", async t => {
  const server = startServer();
  t.after(() => server.kill());
  await waitForHealth(server);

  const health = await fetch(`${baseUrl}/health`, {headers:{"x-request-id":"test-request"}});
  assert.equal(health.status, 200);
  assert.equal((await health.json()).status, "ok");
  assert.equal(health.headers.get("x-request-id"), "test-request");
  assert.equal(health.headers.get("x-content-type-options"), "nosniff");

  const root = await fetch(`${baseUrl}/`, {redirect:"manual"});
  assert.equal(root.status, 302);
  assert.equal(root.headers.get("location"), `${baseUrl}/`);

  const config = await fetch(`${baseUrl}/api/config`);
  assert.equal(config.status, 200);
  const body = await config.json();
  assert.equal(body.limits.free.maxBatchFiles, 5);
  assert.ok(body.limits.converter.maxFileSize > 0);

  const readiness = await fetch(`${baseUrl}/ready`);
  assert.equal(readiness.status, 503);
  assert.equal((await readiness.json()).status, "not_ready");
});

test("public API rejects unsafe conversion and preview inputs", async t => {
  const server = startServer();
  t.after(() => server.kill());
  await waitForHealth(server);

  const conversion = await fetch(`${baseUrl}/api/convert`, {method:"POST", headers:{Origin:baseUrl, "Content-Type":"application/json"}, body:"{}"});
  assert.equal(conversion.status, 400);
  assert.match((await conversion.json()).error, /multipart/i);

  const preview = await fetch(`${baseUrl}/api/preview?url=${encodeURIComponent("https://example.com/file.mp3")}`);
  assert.equal(preview.status, 400);
  assert.match((await preview.json()).error, /Spotify|YouTube|SoundCloud/i);
});