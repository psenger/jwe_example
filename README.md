# JWE RSA Examples

JWE is another form of JWT and JWS. It is an attempt to pass an encrypted payload in a way suitable for JSON json.

## Requirements

This is a Node JS version 12 implementation with OpenSSL. It is version specific, only because the Crypto API has changed. 

## Links I have found helpful

* [My Favorite Examples of JWT and JWE Compact Serialization](https://medium.facilelogin.com/jwt-jws-and-jwe-for-not-so-dummies-b63310d201a3)
* [JSON Web Encryption (JWE) Specification](https://tools.ietf.org/html/rfc7516)
* [Great Examples of 101 Encrypting](https://coolaj86.com/articles/asymmetric-public--private-key-encryption-in-node-js/)
* [Could be good](https://openid.net/specs/draft-jones-json-web-encryption-02.html)
* [Further reading](https://coolaj86.com/articles/asymmetric-public--private-key-encryption-in-node-js/)

## Terms

``RSA`` - is a Symmetrical Certificate. When generated it has both a private key and public key embedded in the Base64 encoded string.

``IV`` - Initial Vector is not commonly used with RSA Encryption. In cipher-block chaining mode (CBC mode), the IV must, in addition to being unique, be unpredictable at encryption time.

``AES`` - AES Encryption, on the other hand, in some modes, for instance CBC or CFB uses IV. These is because AES is a Block Cipher Mode of Operation .

## ENV

``PEM_PASSWORD`` - is the pass phrase used to build the pem file.
