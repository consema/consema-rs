# Production-shaped variables override fixture (original, MIT)

region = "eu-central-1"

azs = ["eu-central-1a", "eu-central-1b"]

nat_enabled = true

replicas = 3

cidr_blocks = {
  web = "10.20.1.0/24"
  db  = "10.20.2.0/24"
}

instance_type = "t3.large"

enable_termination_protection = true

backup_retention_days = 14

domain_name = "consema.example.invalid"

ip_whitelist = [
  "203.0.113.0/24",
  "198.51.100.0/24",
]
