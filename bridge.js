"use strict";
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const net = require("node:net");
const dns = require("node:dns").promises;
const crypto = require("node:crypto");

const cwd = process.cwd();
const settingsFile = path.join(cwd, "bridge.local.json");
let settings = {};
try {
  let raw = fs.readFileSync(settingsFile, "utf8");
  raw = raw.replace(/^\uFEFF/, "").trim();
  settings = JSON.parse(raw);
} catch (error) {
  if (error.code !== "ENOENT") {
    console.error("LOCAL_CONFIG_INVALID:", error.message);
    console.error("LOCAL_CONFIG_FIX: replace bridge.local.json with one JSON object only; no markdown fences, comments, or extra text.");
    process.exit(1);
  }
}
const port = Number(process.env.SERVER_PORT || process.env.PORT || settings.port || 2461);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  console.error("INVALID_LISTEN_PORT");
  process.exit(1);
}
const mode = settings.mode === "ssh" ? "ssh" : "health";

function publicIPv4(address) {
  if (net.isIP(address) !== 4) return false;
  const [a, b, c] = address.split(".").map(Number);
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && (b === 0 || (b === 168) || (b === 88 && c === 99))) return false;
  if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}
function validRemoteName(host) {
  if (typeof host !== "string" || host.length > 253 || !host.trim()) return false;
  if (host.includes("..") || host.endsWith(".local") || host.endsWith(".localhost")) return false;
  if (net.isIP(host)) return publicIPv4(host);
  return /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(host) && host.includes(".");
}
function sameSecret(a, b) {
  const x = crypto.createHash("sha256").update(String(a)).digest();
  const y = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}
function startHealth() {
  const server = http.createServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
    response.end("PulsarCloud network test OK\n");
  });
  server.listen(port, "0.0.0.0", async () => {
    console.log("MODE: health");
    console.log("LISTEN_OK:", port);
    try {
      const result = await fetch("https://example.com", { signal: AbortSignal.timeout(8000) });
      console.log("EGRESS_OK:", result.status);
    } catch (error) {
      console.warn("EGRESS_FAILED:", error.message);
    }
  });
}
function startSSH() {
  if (settings.providerPermissionConfirmed !== true) {
    console.error("SSH_NOT_STARTED: confirm that the hosting provider permits private SSH forwarding.");
    process.exit(2);
  }
  const username = String(settings.username || "bridge");
  const password = settings.password;
  if (typeof password !== "string" || password.length < 24 || password.length > 256) {
    console.error("SSH_NOT_STARTED: bridge.local.json requires a unique 24+ character password.");
    process.exit(2);
  }
  const { Server, utils } = require("ssh2");
  const stateDir = path.join(cwd, ".private");
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const keyFile = path.join(stateDir, "ssh-host-key.pem");
  if (!fs.existsSync(keyFile)) {
    const generated = crypto.generateKeyPairSync("rsa", {
      modulusLength: 3072,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "pkcs1", format: "pem" }
    });
    fs.writeFileSync(keyFile, generated.privateKey, { flag: "wx", mode: 0o600 });
  }
  const hostKey = fs.readFileSync(keyFile);
  const parsedKey = utils.parseKey(hostKey);
  if (parsedKey instanceof Error) throw parsedKey;
  const fingerprint = crypto.createHash("sha256")
    .update(parsedKey.getPublicSSH()).digest("base64").replace(/=+$/, "");
  console.log("SSH_HOST_FINGERPRINT_SHA256:", fingerprint);
  const failures = new Map();
  const supportedAuth = ["password", "keyboard-interactive"];
  let totalChannels = 0;
  const server = new Server({ hostKeys: [hostKey], readyTimeout: 20000 }, (client) => {
    const remoteIP = client._sock?.remoteAddress;
    const ip = typeof remoteIP === "string" && net.isIP(remoteIP) ? remoteIP : null;
    let authenticated = false;
    let ownChannels = 0;
    let anonymousFailures = 0;
    client.on("error", () => {});
    client.on("authentication", (ctx) => {
      const now = Date.now();
      const record = ip
        ? (failures.get(ip) || { since: now, count: 0 })
        : { since: now, count: anonymousFailures };
      if (now - record.since > 600000) { record.since = now; record.count = 0; }
      const deny = (reason, countAttempt) => {
        if (countAttempt) {
          record.count++;
          if (ip) {
            if (failures.size > 1000) failures.clear();
            failures.set(ip, record);
          } else anonymousFailures = record.count;
        }
        // Authentication telemetry: method and outcome only. Never log
        // passwords, submitted responses, source IPs, or usernames.
        console.log("AUTH_REJECT method=" + ctx.method + " reason=" + reason);
        ctx.reject(supportedAuth);
      };
      if (!supportedAuth.includes(ctx.method)) {
        // Clients typically probe "none" and keys before trying a password.
        // Unsupported probes must NOT count as incorrect passwords.
        return deny("unsupported-method", false);
      }
      if (record.count >= 5) return deny("rate-limited", false);
      const checkPassword = (candidate) => {
        if (ctx.username === username && typeof candidate === "string" &&
            sameSecret(candidate, password)) {
          authenticated = true;
          if (ip) failures.delete(ip);
          console.log("AUTH_ACCEPT method=" + ctx.method);
          return ctx.accept();
        }
        deny("credentials-rejected", true);
      };
      if (ctx.method === "password") return checkPassword(ctx.password);
      // Termius and other SSH clients may use keyboard-interactive instead
      // of the RFC 4252 password method. Prompt without echoing user input.
      ctx.prompt([{ prompt: "Password: ", echo: false }], "SSH authentication", "",
        (responses) => checkPassword(Array.isArray(responses) ? responses[0] : undefined));
    });
    client.on("ready", () => {
      if (!authenticated) { client.end(); return; }
      client.on("session", (accept) => {
        const session = accept();
        session.on("pty", (a) => a());
        session.on("shell", (a) => {
          const stream = a();
          stream.write("Private SSH forwarding endpoint. No system shell is provided.\r\n");
          stream.on("data", (data) => {
            if (/^(exit|logout|quit)\s*$/i.test(String(data).trim())) stream.end();
          });
        });
      });
      client.on("tcpip", async (accept, reject, info) => {
        const targetPort = Number(info.destPort);
        const host = String(info.destIP || "");
        if (![80, 443].includes(targetPort) || !validRemoteName(host) ||
            ownChannels >= 8 || totalChannels >= 24) {
          reject();
          return;
        }
        ownChannels++;
        totalChannels++;
        let finished = false;
        let accepted = false;
        function finish() {
          if (!finished) { finished = true; ownChannels--; totalChannels--; }
        }
        try {
          const addresses = net.isIP(host) === 4
            ? [{ address: host }]
            : await dns.lookup(host, { family: 4, all: true });
          if (!addresses.length || addresses.some(({ address }) => !publicIPv4(address))) {
            reject();
            finish();
            return;
          }
          const remote = net.createConnection({
            host: addresses[0].address,
            port: targetPort,
            timeout: 10000
          });
          remote.once("connect", () => {
            accepted = true;
            const channel = accept();
            remote.setTimeout(0);
            remote.pipe(channel).pipe(remote);
            channel.on("error", () => remote.destroy());
            channel.on("close", () => remote.destroy());
          });
          remote.on("error", () => {
            if (!accepted) { try { reject(); } catch (_) {} }
            remote.destroy();
          });
          remote.on("timeout", () => remote.destroy());
          remote.on("close", finish);
        } catch (error) {
          try { reject(); } catch (_) {}
          finish();
        }
      });
    });
  });
  server.on("error", (error) => console.error("SSH_SERVER_ERROR:", error.message));
  server.listen(port, "0.0.0.0", () => {
    console.log("MODE: authenticated-ssh-forward");
    console.log("SSH_LISTEN_OK:", port);
    console.log("SSH_USERNAME:", username);
    console.log("FORWARD_PORTS: TCP 80,443 only; no UDP; no system shell");
  });
}
function start() {
  if (mode === "ssh") startSSH(); else startHealth();
}
if (require.main === module) start();
module.exports = { publicIPv4, validRemoteName, sameSecret, start };
