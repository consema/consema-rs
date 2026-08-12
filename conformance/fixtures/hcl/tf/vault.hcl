# Vault-style server configuration (original fixture, MIT)

ui = true

storage "raft" {
  path = "/opt/vault/data"
  node_id = "node-1"
}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = false
  tls_cert_file = "/opt/vault/tls/server.crt"
  tls_key_file  = "/opt/vault/tls/server.key"
}

seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "alias/consema-vault"
}

api_addr         = "https://127.0.0.1:8200"
cluster_addr     = "https://127.0.0.1:8201"
disable_mlock    = true
log_level        = "info"
max_lease_ttl    = "768h"
default_lease_ttl = "168h"
