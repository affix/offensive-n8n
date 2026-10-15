<p align="center">
  <img src="assets/logo.png" alt="Offensive N8N" width="600">
</p>

Ansible project that turns a Kali Linux machine, arm64 or amd64, into a LAN-only n8n box for offensive workflows. n8n runs natively on the host under systemd, not in Docker, so the Execute Command node can run Kali's own tools directly. Docker is still installed for running tool containers on demand.

## What gets deployed

| Role | Does |
|---|---|
| `base` | apt full-upgrade, timezone, zram swap (zstd, ~50% RAM), nftables default-deny firewall, optional SSH hardening |
| `docker` | Docker CE from Docker's apt repo (not `docker.io`), buildx and compose plugins |
| `n8n` | Node.js from NodeSource, n8n pinned via npm, Python task runner, `n8n` system user, systemd unit, env file, scoped sudoers, Caddy reverse proxy |
| `tooling` | Kali tool packages, qemu binfmt handlers for amd64 emulation on arm64 hosts, nuclei templates |
| `postgres` | Optional PostgreSQL container for workflow data |
| `autossh` | Optional persistent SSH tunnel |
| `ghidra` | Optional headless Ghidra pinned by checksum on JDK 21, natives built on arm64, decompiler smoke test as the service user |
| `patchdiff` | Optional patch diff pipeline: `pd` stage scripts in a pinned uv project with ghidriff, pyghidra, jadx, a sandboxed unblob image and an ilspycmd image |
| `pd_worker` | Worker image only (see [`pd-worker`](pd-worker/README.md)): service user and uv, without n8n |

## Requirements

- Kali on arm64 or amd64 with systemd, reachable over SSH with key auth as a sudo user. A Raspberry Pi 5 works well; so does an amd64 VM or server. **32-bit ARM, WSL and containers are not supported.**
- Ansible on the control node.

```
ansible-galaxy collection install -r requirements.yml
```

## Running it

Copy the example config, then set your host, user, network and URLs:

```
cp inventory.dist.yaml inventory.yaml
cp group_vars/all.dist.yaml group_vars/all.yaml
```

Both copies are gitignored. Then:

```
ansible-playbook site.yml --syntax-check
ansible-playbook site.yml --check --diff
ansible-playbook site.yml --diff
```

Re-runs are idempotent. n8n only restarts when the env file, the systemd unit, or the pinned n8n version changes. Caddy only reloads when the Caddyfile changes.

## Key variables

All tunables live in `group_vars/all.yaml`. Defaults and comments are in `group_vars/all.dist.yaml`.

| Variable | Purpose |
|---|---|
| `n8n_bind_ip` | The only address n8n and Caddy listen on. `127.0.0.1` makes it on-box only. |
| `n8n_port` | n8n listen port, default 5678. |
| `n8n_hostname`, `caddy_http_port` | Internal Caddy vhost and its port. |
| `n8n_behind_proxy`, `n8n_proxy_hops` | Whether an external reverse proxy fronts n8n, and how many proxy hops to trust. Off by default, so n8n advertises its own LAN address. |
| `n8n_public_host`, `n8n_public_url` | External URL n8n advertises for the editor and webhooks when `n8n_behind_proxy` is true. |
| `lan_mgmt_cidr` | Only source range allowed inbound to SSH, n8n and Caddy. |
| `n8n_proxy_cidrs` | Extra sources allowed to the n8n port only, such as a remote reverse proxy arriving over a tunnel. Empty by default. |
| `n8n_dir`, `n8n_data_dir` | Install dir (also the service user's home and `N8N_USER_FOLDER`) and state dir. |
| `loot_dir` | Output dir. The only path the Read/Write Files node can touch. |
| `n8n_user`, `n8n_group` | Service account. Member of the `docker` group. |
| `n8n_sudo_commands` | Full paths the service user may run with `sudo -n`. Defaults to nmap, masscan, naabu. |
| `n8n_nodes_exclude` | Value of `NODES_EXCLUDE`. `[]` re-enables Execute Command, Read/Write Files and Local File Trigger. |
| `n8n_version`, `nodejs_major` | Pinned n8n release and Node.js major. n8n 2.42 needs Node.js 24 or later. |
| `uv_version`, `n8n_py_runner_python` | uv release and interpreter used to build the Python task runner. |
| `n8n_py_stdlib_allow`, `n8n_py_external_allow` | Import allowlists for the Python Code node. Stdlib defaults to `*`, external packages to none. |
| `kali_tool_packages` | Kali packages installed for use from Execute Command. |
| `binfmt_image` | Pinned image that registers qemu handlers. |
| `docker_apt_codename` | Debian codename for Docker's repo. Kali's own codename is not published by Docker. |
| `harden_ssh` | Gate for key-only, no-root SSH. Leave off until key auth is confirmed. |
| `postgres_enabled`, `postgres_image` | Gate and pinned image for a PostgreSQL container (Docker Compose) that workflows use for larger data. Off by default. |
| `postgres_dir` | Compose file, data directory and generated password file. Read the password with `sudo cat /opt/postgres/postgres_password`. |
| `postgres_bind_ip`, `postgres_port` | Published address, loopback by default. |
| `postgres_db`, `postgres_user` | Database and role created on first start. |
| `postgres_shm_size`, `postgres_settings` | Container shared memory and server settings passed as `-c` flags. |
| `autossh_enabled`, `autossh_service_name` | Gate and systemd unit name for a persistent autossh tunnel. Off by default. |
| `autossh_user`, `autossh_identity_file` | Local account the tunnel runs as and the key it uses. The key must already exist on the host. |
| `autossh_remote`, `autossh_remote_port` | SSH destination (`user@host`) and port. |
| `autossh_local_forwards` | `ssh -L` specs held open by the tunnel. |
| `ghidra_enabled` | Gate for the `ghidra` role. Off by default. |
| `ghidra_version`, `ghidra_release_date`, `ghidra_sha256` | Pinned Ghidra release and its checksum from the release notes. |
| `ghidra_gradle_sha256` | Checksum of the Gradle distribution the wrapper downloads when building natives on arm64. |
| `ghidra_base_dir`, `ghidra_install_dir` | Versions unpack side by side under the base dir; the install dir is the `current` symlink and becomes `GHIDRA_INSTALL_DIR`. |
| `ghidra_jdk_package`, `ghidra_java_home` | JDK Ghidra is pinned to via `JAVA_HOME_OVERRIDE`, independent of the distro default JDK. |
| `ghidra_maxmem` | Java heap for headless analysis and ghidriff. Defaults to RAM minus 3GB, at least 2GB. |
| `ghidra_keep_previous` | Keep the previous Ghidra after an upgrade. Cached projects are upgraded on open and cannot go back, so only set false once the new version has run cleanly. |
| `patchdiff_enabled` | Gate for the `patchdiff` role. Off by default; needs `ghidra_enabled`. |
| `patchdiff_dir`, `patchdiff_loot_dir` | Scripts, uv project and tool config, and the job output tree under `loot_dir`. |
| `patchdiff_python` | Interpreter for the venv. Stays on 3.13 because JPype has no 3.14 wheel. |
| `patchdiff_ghidriff_ref`, `patchdiff_pyghidra_version`, `patchdiff_python_deps` | Pinned ghidriff commit, pyghidra and other Python dependencies. |
| `patchdiff_jadx_version`, `patchdiff_jadx_sha256` | Pinned jadx for JAR and APK decompilation. |
| `patchdiff_unblob_image` | Digest-pinned unblob image used as a `--network none` unpacking sandbox. |
| `patchdiff_ilspy_version`, `patchdiff_dotnet_sdk_image` | ilspycmd release and the pinned .NET SDK image it is built on. |
| `patchdiff_ollama_url`, `patchdiff_ollama_model` | Ollama endpoint and model for the triage stage. |
| `patchdiff_packages` | Host unpackers kept for manual triage. |

No image anywhere in the project uses the `latest` tag.

## Using host commands from n8n

Execute Command runs as the `n8n` user with `HOME=/opt/n8n`. Tools on the host `PATH` work directly:

```
subfinder -d example.com -silent | httpx -silent -o /opt/loot/live.txt
```

Raw-socket scans go through the scoped sudo rule:

```
sudo -n nmap -sS -p- --min-rate 2000 -oX /opt/loot/scan.xml 10.0.0.0/24
```

Containers still work because the user is in the `docker` group:

```
docker run --rm -v /opt/loot:/loot projectdiscovery/katana:v1.8.0 -u https://example.com -o /loot/katana.txt
```

## Workflows

`workflows/` holds ready-to-import n8n workflows built for this host, grouped as they are in n8n. Each folder has a README covering what every workflow does, the data tables and Postgres tables to create, and the import order.

| Folder | What it does |
|---|---|
| [`asm-pipeline`](workflows/asm-pipeline/README.md) | External attack surface pipeline: scoped discovery, takeover checks, port scans, web fingerprinting, diffing, vuln checks, Ollama triage and Discord alerts, plus CVE Watch, housekeeping, scope expiry and client PDF reports. |
| [`wazuh-triage`](workflows/wazuh-triage/README.md) | Polls the Wazuh indexer, dedupes and suppresses high-severity alerts, enriches source IPs, LLM-triages the rest and pages only on escalations. Also analyses web honeypot payloads. |
| [`subdomain-takeover`](workflows/subdomain-takeover/README.md) | Scheduled and one-off subdomain takeover monitoring for a list of root domains. |
| [`patch-diff`](workflows/patch-diff/README.md) | Watches products for new releases, diffs each version against the last (source hunks or Ghidra function diffs), matches advisories, LLM-triages candidates and flags likely silent security fixes. Can offload the heavy stages to a throwaway DigitalOcean worker. |
| [`threat-intel`](workflows/threat-intel/README.md) | IP reputation from AbuseIPDB, VirusTotal, GreyNoise and OTX, as a sub-workflow and an IP or domain report form. |

The exports are sanitised. After importing, replace the placeholders (`OLLAMA_HOST`, `OLLAMA_MODEL`, `WAZUH_INDEXER`, `DISCORD_*`, `DATA_TABLE_*`, `CREDENTIAL_ID`) as described in each folder's README. Workflow IDs are kept so sub-workflow calls resolve, which also means importing into an instance that already has them overwrites the existing copies. The Wazuh and patch diff workflows need the `postgres` role enabled.

## Patch diffing

With `ghidra_enabled` and `patchdiff_enabled` set, the host gets headless Ghidra and the `pd` wrapper, which the patch diff workflows call from Execute Command:

```
pd {fetch|unpack|diff|advisory|triage|housekeeping} --job-dir <dir> --product <name> --old <ver> --new <ver>
```

Each stage reads `<run_dir>/config.json` written by the orchestrator, writes a small `result.json` to the job dir and leaves everything else on disk under `patchdiff_loot_dir`. Archives other than plain zip, tar and deb are unpacked inside the unblob container with no network. The triage stage is advisory only and never drops a candidate.

Ghidra analysis is heavy for a Pi. [`pd-worker`](pd-worker/README.md) builds a cloud image with the same stack so the stages can run on a throwaway AWS or DigitalOcean worker instead.

## Backups

`/opt/n8n/.n8n` holds the SQLite database, every credential, and the encryption key that decrypts them. It is the only thing that needs backing up. Keep the backup encrypted and off the box. Restoring that directory onto a fresh install brings back all workflows and credentials.

## Security model

- n8n and Caddy bind `n8n_bind_ip` only. Nothing listens on `0.0.0.0`.
- nftables drops all inbound traffic except loopback, established flows, ICMP, SSH, n8n and Caddy from `lan_mgmt_cidr`, and the n8n port from `n8n_proxy_cidrs`.
- The `n8n` user is root-equivalent. It runs arbitrary host commands, is in the `docker` group, and has passwordless sudo for scanners. Anyone with an n8n login effectively has root on the host. Never expose this box beyond the LAN.
- The systemd unit deliberately has no sandboxing directives, because they would cut Execute Command off from the host.

## Checking it works

```
ss -tlnp | grep -E ':5678|:80 '
systemctl status n8n caddy
journalctl -u n8n -f
sudo -u n8n sudo -n nmap -sS -p 22 127.0.0.1
```

In the editor, confirm Execute Command shows up in the node panel and can run `nmap --version`.

## Troubleshooting

**Python Code node says the runner is unavailable.** The npm package does not ship n8n's Python runner, so the playbook builds it from the n8n source tag into the global node_modules directory. Check that `.venv/bin/python` exists under `@n8n/task-runner-python` there, and re-run the playbook.

**Execute Command is missing from the node panel.** Check that `NODES_EXCLUDE=[]` is in `/etc/n8n/n8n.env` and restart n8n.

**n8n fails to start after an upgrade.** Check `journalctl -u n8n`. A Node.js major outside n8n's supported range is the usual cause, and n8n logs the range it wants. Set `nodejs_major` to match and re-run; the playbook upgrades Node.js and rebuilds n8n's native modules.

## Licence

MIT. See `LICENSE`.
