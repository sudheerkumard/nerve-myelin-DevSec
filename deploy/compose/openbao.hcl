# Copyright (c) 2026 Sudheer Kumar. SPDX-License-Identifier: AGPL-3.0-only.
# OpenBao for the single-host evaluation stack. Plain HTTP on the internal Docker network only (no host port).
# Production: use the customer's Vault / OpenBao / Azure Key Vault / AWS Secrets Manager instead.
ui            = false
disable_mlock = true
api_addr      = "http://vault:8200"
cluster_addr  = "http://vault:8201"

storage "raft" {
  path    = "/openbao/data"
  node_id = "myelin-local"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}
