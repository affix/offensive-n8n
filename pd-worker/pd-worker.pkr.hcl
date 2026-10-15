# Bakes the patch diff worker image on AWS and/or DigitalOcean from Debian 13,
# provisioned by playbook.yml with the repo's ghidra/patchdiff roles.
#
#   cd pd-worker && packer init .
#   op run -- packer build -only='*.amazon-ebs.*' .
#   op run -- packer build -only='*.digitalocean.*' .
#   packer build -var aws_arch=arm64 -only='*.amazon-ebs.*' .
#
# Credentials come from the environment only: AWS_PROFILE or AWS_ACCESS_KEY_ID /
# AWS_SECRET_ACCESS_KEY, and DIGITALOCEAN_TOKEN. Tunables come from
# ../group_vars/all.yaml, the same file site.yml uses.

packer {
  required_version = ">= 1.11.0"
  required_plugins {
    amazon = {
      source  = "github.com/hashicorp/amazon"
      version = "~> 1.3"
    }
    digitalocean = {
      source  = "github.com/digitalocean/digitalocean"
      version = "~> 1.4"
    }
    ansible = {
      source  = "github.com/hashicorp/ansible"
      version = "~> 1.1"
    }
  }
}

locals {
  stamp      = formatdate("YYYYMMDD-hhmm", timestamp())
  image_name = "${var.image_prefix}-${local.stamp}"
  tags = {
    Name    = local.image_name
    Role    = "pd-worker"
    Builder = "packer"
  }
}

source "amazon-ebs" "pd-worker" {
  region        = var.aws_region
  instance_type = var.aws_instance_type[var.aws_arch]
  subnet_id     = var.aws_subnet_id != "" ? var.aws_subnet_id : null

  # Official Debian cloud images (https://wiki.debian.org/Cloud/AmazonEC2Image).
  source_ami_filter {
    owners      = ["136693071363"]
    most_recent = true
    filters = {
      name                = "debian-13-${var.aws_arch}-*"
      architecture        = var.aws_arch == "arm64" ? "arm64" : "x86_64"
      virtualization-type = "hvm"
      root-device-type    = "ebs"
    }
  }

  ssh_username                              = "admin"
  associate_public_ip_address               = true
  temporary_security_group_source_public_ip = true

  launch_block_device_mappings {
    device_name           = "/dev/xvda"
    volume_size           = var.root_volume_gb
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  imds_support = "v2.0"

  ami_name        = "${local.image_name}-${var.aws_arch}"
  ami_description = "Patch diff worker (Debian 13, Ghidra, ghidriff, patchdiff)"
  ami_regions     = var.aws_ami_regions
  encrypt_boot    = true
  tags            = merge(local.tags, { Arch = var.aws_arch })
  run_tags        = local.tags
  snapshot_tags   = local.tags
}

source "digitalocean" "pd-worker" {
  image            = "debian-13-x64"
  region           = var.do_region
  size             = var.do_size
  ssh_username     = "root"
  snapshot_name    = local.image_name
  snapshot_regions = var.do_snapshot_regions
  droplet_name     = "${local.image_name}-build"
  tags             = ["pd-worker", "packer"]
}

build {
  name    = "pd-worker"
  sources = ["source.amazon-ebs.pd-worker", "source.digitalocean.pd-worker"]

  # Let first-boot cloud-init finish so apt is not locked under Ansible.
  provisioner "shell" {
    inline          = ["cloud-init status --wait >/dev/null || true"]
    execute_command = "sudo -S sh -c '{{ .Vars }} {{ .Path }}'"
  }

  provisioner "ansible" {
    playbook_file = "${path.root}/playbook.yml"
    user          = build.User
    groups        = ["pd_worker"]
    use_proxy     = false
    ansible_env_vars = [
      "ANSIBLE_ROLES_PATH=${path.root}/../roles",
      "ANSIBLE_HOST_KEY_CHECKING=False",
      "ANSIBLE_PYTHON_INTERPRETER=/usr/bin/python3",
    ]
  }

  # Strip per-instance state so every launch boots as a fresh instance with new
  # host keys and machine-id, and no build key survives into the image.
  provisioner "shell" {
    execute_command = "sudo -S sh -c '{{ .Vars }} {{ .Path }}'"
    inline = [
      "set -eu",
      "apt-get clean",
      "cloud-init clean --logs --seed --machine-id",
      "rm -f /etc/ssh/ssh_host_*",
      "rm -f /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys",
      "rm -rf /tmp/* /var/tmp/*",
    ]
  }

  post-processor "manifest" {
    output     = "${path.root}/packer-manifest.json"
    strip_path = true
  }
}
