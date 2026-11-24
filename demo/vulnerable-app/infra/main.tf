resource "azurerm_storage_account" "logs" {
  name                            = "paylogs001"
  enable_https_traffic_only       = false
  allow_blob_public_access        = true
  min_tls_version                 = "TLS1_0"
}
resource "azurerm_network_security_rule" "ssh" {
  name = "allow-ssh"  source_address_prefix = "0.0.0.0/0"  destination_port_range = "22"
}
