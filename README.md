# n8n on a Kali Pi

Ansible project that turns a Raspberry Pi 5 running Kali Linux (arm64) into a LAN-only n8n box for offensive workflows. n8n runs natively on the host under systemd, not in Docker, so the Execute Command node can run Kali's own tools directly. Docker is still installed for running tool containers on demand.

## What gets deployed

| Role | Does |
|---|---|
| `base` | apt full-upgrade, timezone, zram swap (zstd, ~50% RAM), nftables default-deny firewall, optional SSH hardening |
| `docker` | Docker CE from Docker's apt repo (not `docker.io`), buildx and compose plugins |
| `n8n` | Node.js from NodeSource, n8n pinned via npm, `n8n` system user, systemd unit, env file, scoped sudoers, Caddy reverse proxy |
| `tooling` | Kali tool packages, qemu binfmt handlers for amd64 emulation, nuclei templates |

## Requirements

- Pi 5 on Kali arm64, reachable over SSH with key auth as a sudo user.
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
| `n8n_public_host`, `n8n_public_url` | External URL n8n advertises for the editor and webhooks. |
| `lan_mgmt_cidr` | Only source range allowed inbound to SSH, n8n and Caddy. |
| `n8n_proxy_cidrs` | Extra sources allowed to the n8n port only, such as a remote reverse proxy arriving over a tunnel. Empty by default. |
| `n8n_dir`, `n8n_data_dir` | Install dir (also the service user's home and `N8N_USER_FOLDER`) and state dir. |
| `loot_dir` | Output dir. The only path the Read/Write Files node can touch. |
| `n8n_user`, `n8n_group` | Service account. Member of the `docker` group. |
| `n8n_sudo_commands` | Full paths the service user may run with `sudo -n`. Defaults to nmap, masscan, naabu. |
| `n8n_nodes_exclude` | Value of `NODES_EXCLUDE`. `[]` re-enables Execute Command, Read/Write Files and Local File Trigger. |
| `n8n_version`, `nodejs_major` | Pinned n8n release and Node.js major. n8n 2.42 needs Node.js 24 or later. |
| `kali_tool_packages` | Kali packages installed for use from Execute Command. |
| `binfmt_image` | Pinned image that registers qemu handlers. |
| `docker_apt_codename` | Debian codename for Docker's repo. Kali's own codename is not published by Docker. |
| `harden_ssh` | Gate for key-only, no-root SSH. Leave off until key auth is confirmed. |

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

## Backups

`/opt/n8n/.n8n` holds the SQLite database, every credential, and the encryption key that decrypts them. It is the only thing that needs backing up. Keep the backup encrypted and off the box. Restoring that directory onto a fresh install brings back all workflows and credentials.

## Security model

- n8n and Caddy bind `n8n_bind_ip` only. Nothing listens on `0.0.0.0`.
- nftables drops all inbound traffic except loopback, established flows, ICMP, SSH, n8n and Caddy from `lan_mgmt_cidr`, and the n8n port from `n8n_proxy_cidrs`.
- The `n8n` user is root-equivalent. It runs arbitrary host commands, is in the `docker` group, and has passwordless sudo for scanners. Anyone with an n8n login effectively has root on the Pi. Never expose this box beyond the LAN.
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

**Execute Command is missing from the node panel.** Check that `NODES_EXCLUDE=[]` is in `/etc/n8n/n8n.env` and restart n8n.

**n8n fails to start after an upgrade.** Check `journalctl -u n8n`. A Node.js major outside n8n's supported range is the usual cause, and n8n logs the range it wants. Set `nodejs_major` to match and re-run; the playbook upgrades Node.js and rebuilds n8n's native modules.
