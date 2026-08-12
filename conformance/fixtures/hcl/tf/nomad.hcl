# Nomad-style job specification (original fixture, MIT)

job "consema-cache" {
  datacenters = ["dc1"]
  type        = "service"

  group "cache" {
    count = 2

    network {
      port "redis" {
        to = 6379
      }
    }

    task "redis" {
      driver = "docker"

      config {
        image = "redis:7-alpine"
        ports = ["redis"]
      }

      env {
        REDIS_REPLICATION_MODE = "master"
      }

      resources {
        cpu    = 500
        memory = 256
      }

      service {
        name = "consema-cache"
        port = "redis"
      }
    }
  }
}
