# Terraform-like network configuration (original fixture, MIT)
# Exercises count, for_each, splats, and conditional expressions.

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "private" {
  count             = length(var.azs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index + 1)
  availability_zone = var.azs[count.index]
}

resource "aws_subnet" "public" {
  for_each          = toset(var.azs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, index(var.azs, each.key) + 101)
  availability_zone = each.key
  map_public_ip     = true
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = var.nat_enabled ? aws_nat_gateway.main[0].id : null
  }
}

resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

locals {
  public_subnet_ids = [for subnet in aws_subnet.public : subnet.id]
  all_subnet_ids    = concat(aws_subnet.private[*].id, local.public_subnet_ids)
}
