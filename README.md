# vp — PulsarCloud private SSH forwarding (opt-in)

This repository is intended for the user's **PulsarCloud Node.js container**, not for the existing Altare sandbox.

## Important distinction

Original known-working path: **Android V2RayTun -> local SOCKS5 127.0.0.1:1080 -> Termius SSH Dynamic forwarding -> Altare Ubuntu -> Internet**.

This project experiments with an authenticated **SSH protocol server implemented using Node.js** so the mobile Termius workflow could remain the same. This is *not* an Ubuntu shell, and not the platform's SFTP endpoint. It supports only SSH password authentication plus outbound `direct-tcpip` to TCP 80/443; it does **not** offer an OS shell, UDP forwarding, reverse tunnels, or remote port binding.

**Deployment and functional compatibility on PulsarCloud have NOT yet been independently verified.** Provider authorization for running a private forwarder has not been established. Do not enable SSH mode without checking the service's acceptable-use policy or obtaining permission.

## Setup — mobile only

For easier phone-only installation, paste the following small loader into your existing `/home/container/index.js`. It downloads the reviewed GitHub bootstrap into `vp-bootstrap.js`, which in turn fetches the application files on each start. It does **not** automatically enable SSH/proxy mode.

```js
(async () => {
  const url = "https://raw.githubusercontent.com/initial2024/vp/4b7af715c167a2274f56560cdd32d3d6cb502bb4/index.js";
  const response = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(20000) });
  if (!response.ok) throw Error("GitHub bootstrap failed: " + response.status);
  require("node:fs").writeFileSync("vp-bootstrap.js", await response.text());
  require("./vp-bootstrap.js");
})().catch(error => { console.error("DEPLOY_FAILED:", error.message); process.exitCode = 1; });
```

You can instead paste the full [index.js](https://raw.githubusercontent.com/initial2024/vp/main/index.js) directly. Do not put secrets in the loader.


1. In [PulsarCloud](https://sole.pulsarcloud.xyz/) open your server **Files**, backing up the existing `index.js`.
2. Replace **only** `/home/container/index.js` with [this repo's index.js](https://raw.githubusercontent.com/initial2024/vp/main/index.js). Set the Startup **MAIN_FILE** to `index.js`.
3. Click Start. The first start downloads `bridge.js` and `package.json` from this public repository and runs `npm install` if necessary. Later starts pull those files again. Local private settings are never fetched or overwritten. You should see `GITHUB_DEPLOY_OK`, `MODE: health`, and `LISTEN_OK: 2461` (or your allocated port).
4. To stay in safe diagnostic mode, do nothing else. In a browser, `http://sgp-1.plutobyte.eu.cc:2461/` should show `PulsarCloud network test OK`. This is **not** a VPN/proxy.
5. **Only after confirming explicit permission from the hosting provider to run an authenticated personal SSH forwarder**, create `bridge.local.json` in the server's Files panel with:

```json
{
  "mode": "ssh",
  "providerPermissionConfirmed": true,
  "username": "bridge",
  "password": "REPLACE_WITH_A_UNIQUE_RANDOM_32_PLUS_CHARACTER_SECRET"
}
```

The file is intentionally ignored by Git. Never put a real password into the public repo or into screenshots.
6. Restart. Check `SSH_LISTEN_OK: 2461` and `SSH_HOST_FINGERPRINT_SHA256`. Note that HTTP diagnostic access stops on that port in SSH mode.
7. In Termius, create a *new* SSH Host at `sgp-1.plutobyte.eu.cc` port `2461` with username `bridge` and the locally generated password. Confirm the remote host key fingerprint. The port `2022` displayed under PulsarCloud **SFTP Access** is **not** this service.
8. Stop the **AL** Termius Dynamic rule before starting a PulsarCloud Dynamic rule on `127.0.0.1:1080`; only one process can bind the local port. Leave V2RayTun pointing at SOCKS5 `127.0.0.1:1080`, and exclude Termius from its VPN routing to prevent loops.
9. Test TCP websites. If it fails, switch back to AL. Do not assume SSH implementation compatibility or provider support until tested.

### Renewal, limitations and safety

- PulsarCloud free servers must be renewed every 72 hours (based on the user's displayed panel); keep AL as the primary node.
- Provider must permit SSH forwarding and proxy use; a working public port alone is not permission.
- The server restricts forwarding to TCP ports 80/443, limits concurrent channels, rejects private/loopback/reserved IPv4 destinations, and does not expose a system shell. IPv6 and UDP are unsupported.
- The SSH host key is generated on first start in `.private/ssh-host-key.pem` and should remain stable while the container's files are retained. If the host key changes unexpectedly, investigate; never blindly accept new keys.
- Do **not** publish `bridge.local.json`, host keys, passwords, V2RayTun subscription URLs or authentication material.
- To roll back, put the backed-up original `index.js` back and remove/disable the local SSH settings.
- `AUTO_UPDATE` in some Pterodactyl eggs only does `git pull` if `.git` exists. This repository's `index.js` bootstrap downloads trusted named files on startup to work without Git shell access. For reproducibility, set optional `VP_REF` to a reviewed commit SHA rather than the moving `main` branch.
- This is a limited prototype, not an audited production VPN. Unit checks: `npm test`. Live SSH/Termius integration is a separate acceptance gate.
