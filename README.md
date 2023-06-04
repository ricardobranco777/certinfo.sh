![Build Status](https://github.com/ricardobranco777/certinfo.sh/actions/workflows/ci.yml/badge.svg)

# certinfo.sh
This script parses PEM or DER certificates, requests, CRL's, PKCS#12, PKCS#7 &amp; PKCS#8 files, Java keystores, NSS databases, Diffie-Hellman / DSA / Elliptic Curve parameters and private &amp; public keys (from OpenSSH too). It uses OpenSSL for most operations (unless the openssl variable is empty), otherwise it uses GnuTLS' certtool. If the certtool variable is empty, Java's keytool is used instead.

# Usage:
certinfo.sh FILE [PASSWORD|PASSWORD_FILE]

certinfo.sh -h [https://]SERVER[:PORT]

certinfo.sh CRL [CAfile]
