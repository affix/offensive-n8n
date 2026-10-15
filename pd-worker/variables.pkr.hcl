variable "image_prefix" {
  type    = string
  default = "pd-worker"
}

variable "root_volume_gb" {
  type        = number
  default     = 40
  description = "Ghidra, the JDK, the venv and the unblob/ilspycmd images need roughly 15GB before any loot."
}

# --- AWS ---------------------------------------------------------------------

variable "aws_region" {
  type    = string
  default = "eu-west-2"
}

variable "aws_arch" {
  type        = string
  default     = "amd64"
  description = "amd64 or arm64 (Graviton). arm64 builds the Ghidra natives with Gradle, which adds 20-40 minutes."
  validation {
    condition     = contains(["amd64", "arm64"], var.aws_arch)
    error_message = "The aws_arch must be amd64 or arm64."
  }
}

variable "aws_instance_type" {
  type        = map(string)
  default     = { amd64 = "c7i.xlarge", arm64 = "c7g.xlarge" }
  description = "Build instance per architecture. Only used while baking."
}

variable "aws_subnet_id" {
  type        = string
  default     = ""
  description = "Empty uses the default VPC."
}

variable "aws_ami_regions" {
  type        = list(string)
  default     = []
  description = "Extra regions to copy the AMI to."
}

# --- DigitalOcean ------------------------------------------------------------

variable "do_region" {
  type    = string
  default = "lon1"
}

variable "do_size" {
  type    = string
  default = "s-4vcpu-8gb"
}

variable "do_snapshot_regions" {
  type        = list(string)
  default     = []
  description = "Extra regions to copy the snapshot to."
}
