"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { Client } = require("ssh2");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const net = require("node:net");

function allocatePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
}
test("SSH server accepts authenticated client and rejects private destination", { timeout: 25000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pulsar-ssh-test-"));
  const password = "integration-only-not-a-production-secret-123456";
  const port = await allocatePort();
  fs.writeFileSync(path.join(dir, "bridge.local.json"), JSON.stringify({
    mode: "ssh", providerPermissionConfirmed: true, username: "bridge", password
  }));
  const child = spawn(process.execPath, [path.resolve(__dirname, "../bridge.js")], {
    cwd: dir, env: { ...process.env, PORT: String(port) }, stdio: ["ignore", "pipe", "pipe"]
  });
  let logs = "";
  child.stdout.on("data", (chunk) => { logs += chunk.toString(); });
  child.stderr.on("data", (chunk) => { logs += chunk.toString(); });
  try {
    await new Promise((resolve, reject) => {
      const began = Date.now();
      const check = () => {
        if (logs.includes("SSH_LISTEN_OK:")) return resolve();
        if (child.exitCode !== null) return reject(new Error("SSH server exited: " + logs));
        if (Date.now() - began > 12000) return reject(new Error("SSH server timeout: " + logs));
        setTimeout(check, 100);
      };
      check();
    });
    const result = await new Promise((resolve, reject) => {
      const client = new Client();
      client.once("error", reject);
      client.once("ready", () => {
        client.forwardOut("127.0.0.1", 20001, "127.0.0.1", 80, (error, stream) => {
          if (stream) stream.end();
          client.end();
          resolve({ error });
        });
      });
      client.connect({
        host: "127.0.0.1", port, username: "bridge", password,
        readyTimeout: 10000,
        hostVerifier: () => true // CI-only, never use this in a real client
      });
    });
    assert.ok(result.error, "Forward to private IP must be rejected");
    assert.match(logs, /SSH_HOST_FINGERPRINT_SHA256:/);
    assert.match(logs, /AUTH_ACCEPT method=password/);

    // Exercise a client preferring keyboard-interactive, with an initial
    // none probe. This must NOT trigger the password failure counter.
    await new Promise((resolve, reject) => {
      const client = new Client();
      client.once("error", reject);
      client.on("keyboard-interactive", (_name, _instructions, _lang, prompts, finish) => {
        assert.equal(prompts.length, 1);
        assert.equal(prompts[0].echo, false);
        finish([password]);
      });
      client.once("ready", () => { client.end(); resolve(); });
      client.connect({
        host: "127.0.0.1", port, username: "bridge",
        authHandler: ["none", "keyboard-interactive"],
        tryKeyboard: true, readyTimeout: 10000,
        hostVerifier: () => true // CI-only, never use for end-user SSH
      });
    });
    assert.match(logs, /AUTH_REJECT method=none reason=unsupported-method/);
    assert.match(logs, /AUTH_ACCEPT method=keyboard-interactive/);
  } finally {
    child.kill("SIGTERM");
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
