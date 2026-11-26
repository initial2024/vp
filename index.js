"use strict";
// First upload only this file as /home/container/index.js.
// On each start it downloads app code from the user's public GitHub repository.
// No password, host key, or device identity is fetched from or sent to GitHub.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const cp = require("node:child_process");

const root = process.cwd();
const ref = process.env.VP_REF || "main";
if (!/^[a-zA-Z0-9._-]{1,80}$/.test(ref) || ref.includes("..")) {
  console.error("INVALID_GITHUB_REF");
  process.exit(1);
}
const remoteBase = "https://raw.githubusercontent.com/initial2024/vp/" + ref + "/";
const allowedFiles = ["bridge.js", "package.json"];
async function getSource(file) {
  const response = await fetch(remoteBase + file, {
    redirect: "error",
    signal: AbortSignal.timeout(20000),
    headers: { "cache-control": "no-cache" }
  });
  if (!response.ok) throw Error("GITHUB_FETCH_FAILED " + file + " HTTP " + response.status);
  const body = await response.text();
  if (!body || body.length > 500000) throw Error("BAD_SOURCE_SIZE " + file);
  return body;
}
async function main() {
  const downloads = await Promise.all(allowedFiles.map(getSource));
  const hash = crypto.createHash("sha256").update(downloads[1]).digest("hex");
  for (let i = 0; i < allowedFiles.length; i++) {
    const destination = path.join(root, allowedFiles[i]);
    const temp = destination + ".download";
    fs.writeFileSync(temp, downloads[i], { mode: 0o600 });
    fs.renameSync(temp, destination);
  }
  const marker = path.join(root, ".vp-package-sha256");
  const oldHash = fs.existsSync(marker) ? fs.readFileSync(marker, "utf8").trim() : "";
  if (oldHash !== hash || !fs.existsSync(path.join(root, "node_modules", "ssh2"))) {
    console.log("DEPENDENCIES_INSTALLING");
    cp.execFileSync("npm", ["install", "--omit=optional", "--no-audit", "--no-fund"], {
      cwd: root, stdio: "inherit", timeout: 120000
    });
    fs.writeFileSync(marker, hash + "\n", { mode: 0o600 });
  }
  const codeHash = crypto.createHash("sha256").update(downloads[0]).digest("hex");
  console.log("GITHUB_DEPLOY_OK: " + ref + " bridge.js SHA256 " + codeHash.slice(0, 16));
  require(path.join(root, "bridge.js")).start();
}
main().catch((error) => {
  console.error("BOOTSTRAP_FAILED:", error.message);
  process.exitCode = 1;
});
