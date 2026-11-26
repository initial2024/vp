"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { Client } = require("ssh2");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const net = require("node:net");
const tls = require("node:tls");

async function freePort() {
  return await new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const port = s.address().port;
      s.close(() => resolve(port));
    });
  });
}

test("authenticated SSH forwards real HTTPS traffic over TCP 443", { timeout: 35000 }, async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-egress-"));
  const port = await freePort();
  const password = "ci-random-local-ssh-test-only-934907329";
  fs.writeFileSync(path.join(root, "bridge.local.json"), JSON.stringify({
    mode: "ssh", providerPermissionConfirmed: true, username: "bridge", password
  }));
  const srv = spawn(process.execPath, [path.join(__dirname, "../bridge.js")], {
    cwd: root,
    env: { ...process.env, PORT: String(port) },
    stdio: ["ignore", "pipe", "pipe"]
  });
  let logs = "";
  srv.stdout.on("data", d => { logs += d.toString(); });
  srv.stderr.on("data", d => { logs += d.toString(); });
  const client = new Client();
  try {
    await new Promise((resolve, reject) => {
      const start = Date.now();
      const check = () => {
        if (logs.includes("SSH_LISTEN_OK:")) return resolve();
        if (srv.exitCode !== null) return reject(new Error(logs));
        if (Date.now() - start > 13000) return reject(new Error("Startup timeout " + logs));
        setTimeout(check, 100);
      };
      check();
    });
    await new Promise((resolve, reject) => {
      client.once("ready", resolve);
      client.once("error", reject);
      client.connect({
        host: "127.0.0.1", port, username: "bridge", password,
        readyTimeout: 9000,
        hostVerifier: () => true // test-only ephemeral server
      });
    });
    await new Promise((resolve, reject) => {
      client.forwardOut("127.0.0.1", 55000, "1.1.1.1", 443, (err, channel) => {
        if (err) return reject(new Error("SSH direct-tcpip rejected: " + err.message + "\n" + logs));
        const secure = tls.connect({
          socket: channel,
          servername: "cloudflare-dns.com",
          timeout: 12000,
          rejectUnauthorized: true
        });
        let gotResponse = false;
        secure.once("secureConnect", () => {
          secure.write("GET / HTTP/1.1\r\nHost: cloudflare-dns.com\r\nConnection: close\r\n\r\n");
        });
        secure.on("data", chunk => {
          if (!gotResponse && /^HTTP\/1\.[01] [1-5][0-9][0-9]/.test(chunk.toString())) {
            gotResponse = true;
            secure.destroy();
            resolve();
          }
        });
        secure.on("timeout", () => { secure.destroy(); reject(new Error("HTTPS response timeout \n" + logs)); });
        secure.on("error", error => reject(new Error("TLS over SSH failed: " + error.message + "\n" + logs)));
        secure.on("end", () => { if (!gotResponse) reject(new Error("No HTTP response over SSH \n" + logs)); });
      });
    });
    assert.match(logs, /AUTH_ACCEPT method=password/);
    assert.match(logs, /FORWARD_REQUEST port=443 type=ipv4/);
    assert.match(logs, /FORWARD_CONNECTED port=443/);
  } finally {
    client.end();
    srv.kill("SIGTERM");
    fs.rmSync(root, { recursive: true, force: true });
  }
});
