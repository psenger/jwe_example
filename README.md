# JWE RSA Examples

Written by Philip A Senger

[philip.a.senger@cngrgroup.com](mailto:philip.a.senger@cngrgroup.com) | mobile: 0404466846 | [LinkedIn](http://au.linkedin.com/in/philipsenger)

JWE is a sub set of JWT and JWS. It is an attempt to pass an encrypted payload in a way suitable for JSON.

## Requirements

This is a Node JS version 12 implementation with OpenSSL. It is version specific, only because the Crypto API for NodeJS has changed significantly. 

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

## Understanding the format

A JWE payload is a set of 5 base64url encoded sections. Each section ( like JWT ) is separated by period. 

* The first section is a JSON object as an encoded UTF8 string representing the Javascript Object Signing and Encryption Header ( JOSE ) and in this example is the blue set. See section JOSE for valid values.
* The second, is CEK or Content Encryption Key, this key is Asymmetrically encrypted and is the key for the content. It changes on every request and in this example is the green set.
* The third set is the Initialization Vector ( IV ) and is a fixed-size random input similar to a nonce used to randomize the content with a "seed". This is used for CGM. In this example it is the color purple.
* The red section is the encrypted content, it is encrypted with the CEK in a Symmetrical key.
* The final section ( orange ), is the authTag which is the message authentication code (MAC) calculated during the encryption.

<span style="color:blue">N0IyMjYxNkM2NzIyM0EyMjUyNTM0MTJENEY0MTQ1NTAyRDMyMzUzNjIyMkMyMjY1NkU2MzIyM0EyMjQxMzIzNTM2NDc0MzREMjI3RA</span>.<span style="color:green">M0VFQzY1QTdGRTlDOTJEQzg4OTc2RTk5RjU4MkYwMjZBNEEyNzIwNkVDNDU3QUJERjA4MDA4MjVBOUJBRDVBRDVDQTFEMTk2NTIzMzgwOTdFRDBBMjQ4N0VBNjZCMjI3REE1RjUzOUI5MDYyQjFGOTk3NERENUU2MjY0QkZFN0I0OTIwQUFCNkNCMDE2ODJCQjQxOEQ5RTIxMEY0MTRDQzA1RDI5NjdBN0UyNjNFQzgyRjlFMzI3NzM3RUY5QjM0MDgxQUI4MzQ1MENGOUQ4QzZCQkFFN0U3REQ0MTJBQUU5RTVDQUY4RjgxNDZBOEU2QjYyRkY0NjI0REM0RkJGMEY0MTIzQTg1QzY2RjhFQzExN0QwMjdGNTIzOTAyMDBERUEyOEY4QjNDNDM1NzU3MzMwNUZFRjVFNzExQ0Q5OEJFMzBGQjJDRDlENTM5MUYwNUZEQTE1OUJGMjU3QkZBODk1OTZDRjQxQzc2MEY2OUI3QTg1Q0RCQkYyRDdENzRGNkU4MzlDNkY1MEFFNkRDQjAzMUMyQTMyRjZDRkEyNkU2ODVFMkZBQkI0NThBM0FBMjgwRUJFQUJFRjI1MEJFQUJCMTYxMkFGMDMzRDk4MTFDOEJEODdENTU2M0QyRTcyNThGMkFEQUUzRDIzNUVGMzI4RDYwQTAzRDkyQkZBNjY</span>.<span style="color:purple">NTUzQzUwQjJFOUQ4RDM5QTFDQTgzQzc2MjE4Q0EyRThCNTY3NTgwMTNDM0EzQjMzNkQxNUM5RUIxQzc4Nzc5OQ</span>.<span style="color:red">ODUyM0E2NTUyNDM2RkI5MjYyQjY0ODgyMjQ1N0Q3MDZCMUFBQzgxNTExRDVGM0MwMjkzQjk1NkExOTNDQURCM0REOUU4MDg0NTk1NUZFNDA1NzQ0MjQxRThBMTM2MDEwQTQ4NzQyRTlBOEU1QzI3NjY4Mjg2NjFEMDhCRTUyRUJBNkMwQjEwRTk5NDU3MDNDNTNFMTgzRUI0RDZDNUY2RjNBQTU1RTM4</span>.<span style="color:orange">QTNEQjM2REI3NTBDQzc1REJFODlDOEVBOTA1RDZBRkY</span>
 
For example:

This first value is a base 64 encoded clear text string that is the JOSE header ( a JSON object ) which describes the encryption for the KEY and the Content Encryption. 
``N0IyMjYxNkM2NzIyM0EyMjUyNTM0MTJENEY0MTQ1NTAyRDMyMzUzNjIyMkMyMjY1NkU2MzIyM0EyMjQxMzIzNTM2NDc0MzREMjI3RA``

This second value is again a base 64 encoded string which contents is a random per request symmetric key ( as described in the JOSE header ) called the CEK which is then asymmetric encrypted ( the format again, is described in the JOSE header ) and base 64 encoded. When the receiver accepts this message, they will use the private key to decrypt the this key, which will then be used to decrypt the content.
``M0VFQzY1QTdGRTlDOTJEQzg4OTc2RTk5RjU4MkYwMjZBNEEyNzIwNkVDNDU3QUJERjA4MDA4MjVBOUJBRDVBRDVDQTFEMTk2NTIzMzgwOTdFRDBBMjQ4N0VBNjZCMjI3REE1RjUzOUI5MDYyQjFGOTk3NERENUU2MjY0QkZFN0I0OTIwQUFCNkNCMDE2ODJCQjQxOEQ5RTIxMEY0MTRDQzA1RDI5NjdBN0UyNjNFQzgyRjlFMzI3NzM3RUY5QjM0MDgxQUI4MzQ1MENGOUQ4QzZCQkFFN0U3REQ0MTJBQUU5RTVDQUY4RjgxNDZBOEU2QjYyRkY0NjI0REM0RkJGMEY0MTIzQTg1QzY2RjhFQzExN0QwMjdGNTIzOTAyMDBERUEyOEY4QjNDNDM1NzU3MzMwNUZFRjVFNzExQ0Q5OEJFMzBGQjJDRDlENTM5MUYwNUZEQTE1OUJGMjU3QkZBODk1OTZDRjQxQzc2MEY2OUI3QTg1Q0RCQkYyRDdENzRGNkU4MzlDNkY1MEFFNkRDQjAzMUMyQTMyRjZDRkEyNkU2ODVFMkZBQkI0NThBM0FBMjgwRUJFQUJFRjI1MEJFQUJCMTYxMkFGMDMzRDk4MTFDOEJEODdENTU2M0QyRTcyNThGMkFEQUUzRDIzNUVGMzI4RDYwQTAzRDkyQkZBNjY``
 
This third value, is again a base 64 encoded string which is the Initialization Vector. A fixed size random value used to ensure the cipher text is never the same when the underlining value is repeated across encryption ( a known security flaw which undermines the security )
``NTUzQzUwQjJFOUQ4RDM5QTFDQTgzQzc2MjE4Q0EyRThCNTY3NTgwMTNDM0EzQjMzNkQxNUM5RUIxQzc4Nzc5OQ`` 
 
This fourth value, is again a base 64 encoded string which is the symmetrically encrypted value ( the key being the CEK ).
``ODUyM0E2NTUyNDM2RkI5MjYyQjY0ODgyMjQ1N0Q3MDZCMUFBQzgxNTExRDVGM0MwMjkzQjk1NkExOTNDQURCM0REOUU4MDg0NTk1NUZFNDA1NzQ0MjQxRThBMTM2MDEwQTQ4NzQyRTlBOEU1QzI3NjY4Mjg2NjFEMDhCRTUyRUJBNkMwQjEwRTk5NDU3MDNDNTNFMTgzRUI0RDZDNUY2RjNBQTU1RTM4``
 
 This last part ( the fifth value ), is again a base 64 encoded string of the Auth Tag. which incorporates check sums and the message authentication code. 
 ``QTNEQjM2REI3NTBDQzc1REJFODlDOEVBOTA1RDZBRkY``
 
## JOSE format

```json
{ 
    "alg": "RSA-OAEP-256", 
    "enc": "A256GCM",
    "zip": "GZIP",
    "cty": "json",
    "kid": "<to be installed and operational later>"
}
```

* _alg_ - RSA-OAEP-256 - RSAES OAEP using SHA-256 and MGF1 with SHA-256 See section [section-4.3 of rfc7518](https://www.rfc-editor.org/rfc/rfc7518#section-4.3) This value is hard coded simply because of the complexity needed to test the variants. This is also an acceptable level of encryption for most civilians and commercial products. 
* _enc_ - AES 256 GCM - encryption of the content. Again, this was chosen, for simplicity and acceptable level of encryption for most civilians and commercial products.
* _zip_ - an optional field that indicates if the content is gziped. I think ( @TODO Phil ) that AES does compression, and that would explain why the size is never smaller than the unziped verison.
* _cty_ - is the mime type of the content, minus the "application/". For example "application/json" is "json" this really is only used to know the string encoding type... which is always UTF8 in this case.
* _kid_ - Key ID. very important if you want to serve multiple keys with this service 

## ENV

``PEM_PASSWORD`` - is the pass phrase used to build the pem file.

## Notes

JWE, can be used to encrypt any mime type ( which can be declared via [cty](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10) in the JOSE header ). However, for simplicity and illustration, these examples assume the content is a UTF-8 String of JSON. 

Furthermore, in this example, I use an optional GZIP for the [zip](https://tools.ietf.org/html/rfc7516#section-4.1.3) declaration.

## TODO

Try to understand a get the [kid](https://tools.ietf.org/html/rfc7516#section-4.1.6) or [jwk](https://tools.ietf.org/html/rfc7516#section-4.1.5) working 

```
4.1.4.  "jku" (JWK Set URL) Header Parameter

   This parameter has the same meaning, syntax, and processing rules as
   the "jku" Header Parameter defined in Section 4.1.2 of [JWS], except
   that the JWK Set resource contains the public key to which the JWE
   was encrypted; this can be used to determine the private key needed
   to decrypt the JWE.

4.1.5.  "jwk" (JSON Web Key) Header Parameter

   This parameter has the same meaning, syntax, and processing rules as
   the "jwk" Header Parameter defined in Section 4.1.3 of [JWS], except
   that the key is the public key to which the JWE was encrypted; this
   can be used to determine the private key needed to decrypt the JWE.

4.1.6.  "kid" (Key ID) Header Parameter

   This parameter has the same meaning, syntax, and processing rules as
   the "kid" Header Parameter defined in Section 4.1.4 of [JWS], except
   that the key hint references the public key to which the JWE was
   encrypted; this can be used to determine the private key needed to
   decrypt the JWE.  This parameter allows originators to explicitly
   signal a change of key to JWE recipients.
```   
