# pd-worker

Packer build for a patch diff worker image: Debian 13 with Docker, headless Ghidra and the `pd` stage scripts, baked as an AWS AMI or a DigitalOcean snapshot. The n8n host drives a worker launched from it over SSH, so heavy Ghidra analysis runs off the Pi. n8n itself is not installed.

## What gets built

Packer launches a Debian 13 instance, runs `playbook.yml` against it, then images it. The playbook installs `gnupg` and `acl` (both missing from the AWS image) and applies these roles from `../roles`:

| Role | Does |
|---|---|
| `docker` | Docker CE from Docker's apt repo |
| `pd_worker` | `n8n` service user in the `docker` group, pinned uv |
| `ghidra` | Pinned Ghidra on JDK 21, natives built on arm64, decompiler smoke test |
| `patchdiff` | `pd` stage scripts, uv venv with ghidriff and pyghidra, jadx, unblob and ilspycmd images, ghidriff and PyGhidra checks |

Before imaging, a cleanup step runs `cloud-init clean --logs --seed --machine-id`, deletes the SSH host keys and every `authorized_keys`, and clears apt and temp files. Each launch boots as a new instance with fresh host keys and only the keys you give it at launch.

| Cloud | Base image | Build instance | Output |
|---|---|---|---|
| AWS | Latest official Debian 13 AMI (owner `136693071363`), amd64 or arm64 | `c7i.xlarge` or `c7g.xlarge`, public IP, SSH open to the build machine's IP only | Encrypted AMI `pd-worker-<stamp>-<arch>`, IMDSv2 required |
| DigitalOcean | `debian-13-x64` | `s-4vcpu-8gb` in `lon1` | Snapshot `pd-worker-<stamp>` |

An amd64 build takes about 7 minutes. arm64 builds the Ghidra natives with Gradle, which adds 20 to 40 minutes.

## Requirements

- Packer 1.11 or later and Ansible on the build machine.
- `../group_vars/all.yaml` filled in. `group_vars` here is a symlink to the repo's, so the worker gets the same pins as `site.yml`. The `ghidra_*`, `patchdiff_*`, `n8n_user`, `n8n_group`, `n8n_dir`, `loot_dir`, `uv_version` and `docker_apt_codename` values are the ones that matter.
- Cloud credentials in the environment only:
  - AWS: `AWS_PROFILE`, or `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`. The default VPC is used unless `aws_subnet_id` is set.
  - DigitalOcean: `DIGITALOCEAN_TOKEN`.

## Building

```
cd pd-worker
packer init .
packer validate .
```

DigitalOcean, with the token from 1Password. Use the item ID in the reference if the vault has archived items with the same name:

```
DIGITALOCEAN_TOKEN='op://<vault>/<item>/<field>' op run -- packer build -only='*.digitalocean.*' .
```

AWS:

```
AWS_PROFILE=<profile> packer build -only='*.amazon-ebs.*' .
AWS_PROFILE=<profile> packer build -only='*.amazon-ebs.*' -var aws_arch=arm64 .
```

Leaving out `-only` builds both. Every build appends its image ID to `packer-manifest.json`, which is gitignored.

## Variables

Set with `-var name=value` or a `*.auto.pkrvars.hcl` file.

| Variable | Default | Purpose |
|---|---|---|
| `image_prefix` | `pd-worker` | Image name prefix. A `YYYYMMDD-hhmm` stamp is appended. |
| `root_volume_gb` | `40` | Root volume size on AWS. The stack needs roughly 15GB before any loot. |
| `aws_region` | `eu-west-2` | Build region. |
| `aws_arch` | `amd64` | `amd64` or `arm64` (Graviton). |
| `aws_instance_type` | `{ amd64 = "c7i.xlarge", arm64 = "c7g.xlarge" }` | Build instance per architecture. Only used while baking. |
| `aws_subnet_id` | `""` | Subnet to build in. Empty uses the default VPC. |
| `aws_ami_regions` | `[]` | Extra regions to copy the AMI to. |
| `do_region` | `lon1` | Build region. |
| `do_size` | `s-4vcpu-8gb` | Build droplet size. |
| `do_snapshot_regions` | `[]` | Extra regions to copy the snapshot to. |

## Using the image

Launch a worker from the AMI or snapshot with your SSH key. The `pd` wrapper is at `/usr/local/bin/pd` and runs stages the same way as on the n8n host, with output under `/opt/loot/patchdiff`. Run stages as the `n8n` user so the Ghidra settings and loot permissions line up.

Workers are meant to be throwaway. Pull results back to the n8n host and destroy the instance when the job is done. Rebuild the image whenever the Ghidra or patchdiff pins in `group_vars` change.

## When a build fails

Packer terminates the instance and removes its temporary key pair and security group on failure, so nothing is left running. The Ansible output in the build log shows the failing task. To keep the instance for debugging, add `-on-error=ask`.

**`Either apt-key or gpg binary is required`.** The base image has no gpg. The playbook installs `gnupg` before the roles; check that pre_task is still there.

**`Failed to set permissions on the temporary files Ansible needs to create when becoming an unprivileged user`.** The build connects as a non-root user (`admin` on AWS) and a task switches to `n8n`, which needs `setfacl`. The same pre_task installs `acl`.

**`No image found` on AWS.** Debian has not yet published an AMI for the chosen architecture in that region. Try another `aws_region`.

**Ghidra smoke test or PyGhidra check fails.** The pinned JDK or `ghidra_maxmem` is usually the cause. A heap larger than the build instance's RAM stops the JVM from starting.
