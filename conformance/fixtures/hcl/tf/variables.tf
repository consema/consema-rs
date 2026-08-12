# Terraform-like variable declarations (original fixture, MIT)

variable "azs" {
  description = "Availability zones for the demo environment"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "nat_enabled" {
  description = "Whether to provision NAT gateways"
  type        = bool
  default     = true
}

variable "instance_type" {
  type    = string
  default = "t3.micro"

  validation {
    condition     = startswith(var.instance_type, "t3")
    error_message = "The demo instance type must be a t3 family."
  }
}

variable "cidr_blocks" {
  type = map(string)
  default = {
    web = "10.0.1.0/24"
    db  = "10.0.2.0/24"
  }
}

variable "replicas" {
  type    = number
  default = 3
}
