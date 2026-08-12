# Production-shaped terraform.tfvars fixture (original, MIT)

region = "us-east-1"

instance_type = "t3.micro"

ami = "ami-0abcdef1234567890"

instance_count = 2

monitoring = true

tags = {
  Name = "web-server"
  Env  = "prod"
  Team = "platform"
}

security_groups = [
  "sg-0123456789abcdef0",
  "sg-1123456789abcdef0",
]

launch_template = {
  id      = "lt-0123456789abcdef0"
  version = 1
}

user_data = <<-EOT
  #!/bin/sh
  echo "provisioned" >> /var/log/consema.log
  EOT
