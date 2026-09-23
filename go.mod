module github.com/Snawoot/opera-proxy

go 1.26.0

// Pin the patch release: go 1.26.0 carries 17 known standard-library
// vulnerabilities (net/url, crypto/tls, crypto/x509, net/http, encoding/asn1)
// that govulncheck reports as reachable from this code. 1.26.8 is clean.
toolchain go1.26.8

require (
	github.com/Snawoot/go-http-digest-auth-client v1.1.3
	github.com/hashicorp/go-multierror v1.1.1
	github.com/ncruces/go-dns v1.3.3
	github.com/things-go/go-socks5 v0.1.3
	golang.org/x/crypto/x509roots/fallback v0.0.0-20260921070245-7a4a4d6beae2
	golang.org/x/net v0.59.0
)

require github.com/hashicorp/errwrap v1.1.0 // indirect
