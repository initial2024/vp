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

const timeout = (ms, task) => Promise.race([
  task,
  new Promise((_, reject) => setTimeout(() => reject(new Error("Timed out after " + ms + "ms")), ms))
]);

function readReply(socket, bytes) {
  return new Promise((resolve, reject) => {
    const onData = (chunk) => {
      socket.off("error", onError);
      if (chunk.length < bytes) return reject(new Error("Truncated SOCKS reply"));
      if (chunk.length > bytes) socket.unshift(chunk.subarray(bytes));
      resolve(chunk.subarray(0, bytes));
    };
    const onError = (error) => {
      socket.off("data", onData);
      reject(error);
    };
    socket.once("data", onData);
    socket.once("error", onError);
  });
}

async function ephemeralPort() {
  const s = net.createServer();
  await new Promise((resolve, reject) => s.listen(0, "127.0.0.1", resolve).once("error", reject));
  const port = s.address().port;
  await new Promise((resolve) => s.close(resolve));
  return port;
}

test("Firefox-style SOCKS5 handshake to TLS website works through SSH forward", { timeout: 45000 }, async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "vp-socks5-"));
  const port = await ephemeralPort();
  const pass = "test-only-private-password-724125672346";
  fs.writeFileSync(path.join(cwd, "bridge.local.json"), JSON.stringify({
    mode: "ssh", providerPermissionConfirmed: true, username: "bridge", password: pass
  }));
  const backend = spawn(process.execPath, [path.join(__dirname, "../bridge.js")], {
    cwd, env: { ...process.env, PORT: String(port) }, stdio: ["ignore", "pipe", "pipe"]
  });
  let logs = "";
  backend.stdout.on("data", (data) => { logs += String(data); });
  backend.stderr.on("data", (data) => { logs += String(data); });
  const ssh = new Client();
  let socks;
  let browser;
  let tlsBrowser;
  try {
    await timeout(14000, new Promise((resolve, reject) => {
      const probe = setInterval(() => {
        if (logs.includes("SSH_LISTEN_OK:")) {
          clearInterval(probe);
          resolve();
        } else if (backend.exitCode !== null) {
          clearInterval(probe);
          reject(new Error("SSH backend exited " + logs));
        }
      }, 100);
    }));
    await timeout(10000, new Promise((resolve, reject) => {
      ssh.once("ready", resolve);
      ssh.once("error", reject);
      ssh.connect({
        host: "127.0.0.1", port, username: "bridge", password: pass,
        readyTimeout: 9000,
        hostVerifier: () => true // strictly test-only ephemeral SSH key
      });
    }));
    // This local-only SOCKS5 listener emulates Termius' Dynamic Forwarding.
    // No HTTP proxy and no Internet-facing unauthenticated listener.
    socks = net.createServer((socket) => {
      socket.once("data", (greeting) => {
        if (!greeting.equals(Buffer.from([5, 1, 0]))) return socket.destroy();
        socket.write(Buffer.from([5, 0])); // no SOCKS authentication
        socket.once("data", (req) => {
          if (req.length < 7 || req[0] !== 5 || req[1] !== 1 || req[3] !== 3) {
            socket.destroy();
            return;
          }
          const len = req[4];
          if (req.length !== 5 + len + 2) return socket.destroy();
          const hostname = req.subarray(5, 5 + len).toString();
          const dstPort = req.readUInt16BE(req.length - 2);
          ssh.forwardOut("127.0.0.1", 55011, hostname, dstPort, (err, channel) => {
            if (err) {
              socket.write(Buffer.from([5, 5, 0, 1, 0, 0, 0, 0, 0, 0]));
              return socket.end();
            }
            socket.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
            channel.pipe(socket).pipe(channel);
            channel.on("error", () => socket.destroy());
            socket.on("error", () => channel.destroy());
          });
        });
      });
      socket.on("error", () => {});
    });
    await new Promise((resolve, reject) => socks.listen(0, "127.0.0.1", resolve).once("error", reject));
    browser = net.createConnection({
      host: "127.0.0.1", port: socks.address().port
    });
    await new Promise((resolve, reject) => browser.once("connect", resolve).once("error", reject));
    let reply = readReply(browser, 2);
    browser.write(Buffer.from([5, 1, 0]));
    assert.deepEqual(await timeout(4000, reply), Buffer.from([5, 0]));
    const host = Buffer.from("cloudflare-dns.com");
    const request = Buffer.concat([
      Buffer.from([5, 1, 0, 3, host.length]), host, Buffer.from([1, 187])
    ]);
    reply = readReply(browser, 10);
    browser.write(request);
    assert.deepEqual(await timeout(14000, reply),
      Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
    tlsBrowser = tls.connect({
      socket: browser, servername: "cloudflare-dns.com", rejectUnauthorized: true
    });
    await timeout(14000, new Promise((resolve, reject) => {
      tlsBrowser.once("secureConnect", () => {
        tlsBrowser.write("GET / HTTP/1.1\r\nHost: cloudflare-dns.com\r\nConnection: close\r\n\r\n");
      });
      tlsBrowser.on("data", (chunk) => {
        if (/^HTTP\/1\.[01] [1-5]\d\d/.test(chunk.toString())) resolve();
      });
      tlsBrowser.once("error", reject);
      tlsBrowser.once("end", () => reject(new Error("No HTTP response through SOCKS5")));
    }));
    assert.match(logs, /FORWARD_REQUEST port=443 type=domain/);
    assert.match(logs, /FORWARD_CONNECTED port=443/);
    assert.match(logs, /FORWARD_CLIENT_PAYLOAD_SEEN/);
    assert.match(logs, /FORWARD_TARGET_PAYLOAD_SEEN/);
  } finally {
    tlsBrowser?.destroy();
    browser?.destroy();
    ssh.end();
    socks?.close();
    backend.kill("SIGTERM");
    fs.rmSync(cwd, { recursive: true, force: true });
  }
});
