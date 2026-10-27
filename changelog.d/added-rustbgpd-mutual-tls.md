### Added

- The rustbgpd action supports remote endpoints over mutual TLS with
  `rustbgpd_tls_ca_file`, `rustbgpd_tls_cert_file` and `rustbgpd_tls_key_file`.
  Configure all three together; the client verifies the server certificate and
  target name, and the private key requires the same owner-only permissions as
  the bearer token. The CA and certificate files must not be writable by group
  or others. A token is needed with mutual TLS only when the rustbgpd listener
  sets `token_file`. Plaintext connections remain limited to Unix sockets or
  literal loopback addresses with a token.
