# Terraform-like module configuration (original fixture, MIT)
# Written for Consema conformance; not a copy of any third-party project.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "instance_count" {
  type    = number
  default = 2
}

variable "common_tags" {
  type = map(string)
  default = {
    Env = "prod"
  }
}

locals {
  name_prefix = "consema-demo"
  all_tags    = merge(var.common_tags, { Name = local.name_prefix })
}

resource "aws_instance" "web" {
  count         = var.instance_count
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  tags          = local.all_tags

  user_data = <<-EOF
    #!/bin/sh
    echo "web-${count.index}" > /etc/hostname
  EOF
}

module "vpc" {
  source  = "./modules/vpc"
  cidr    = "10.0.0.0/16"
  enabled = true
}

output "web_ips" {
  value = aws_instance.web[*].private_ip
}

data "aws_availability_zones" "available" {
  state = "available"
}
