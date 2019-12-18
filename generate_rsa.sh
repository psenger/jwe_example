#!/usr/bin/env bash

# when you generate a RSA key, the key has both the Private and Public Key in the encoded string.
# the second call to openssl merely extracts the public key.
openssl genrsa -out ./privkey.pem 2048
openssl rsa -in ./privkey.pem -pubout -out ./pubkey.pem
