ui            = true
api_addr      = "https://127.0.0.1:8200"
disable_mlock = true

storage "file" {
  path = "./.vault/data"
}

listener "tcp" {
  address         = "127.0.0.1:8200"
  tls_cert_file   = "./cert.pem"
  tls_key_file    = "./key.pem"
}
