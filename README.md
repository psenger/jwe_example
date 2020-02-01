# JWE and JWS - RSA Examples

Written by Philip A Senger

[JSON Web Encryption (JWE)](https://tools.ietf.org/html/rfc7516) and [JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515) are a sub set specification of [JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519). They both are an attempt to pass an encrypted payload and digitally signed payload in a way suitable for JSON.

This project is a proof of concept 

* written in NodesJS 
* using `JWE Compact Serialization` JWE
* With `Key Encryption` key mode Encryption
* RSA with Public and Private Keys
* and finally using a JWS to create a Digital signature.

## Why

I have a need to pass a piece of JSON data over the internet from potentially multiple different sites. This data is private and will sit in a web page and could be hacked, stolen or manipulated.

Encrypting the data is an option, but a mechanism already exists to move data securely, JWE and JWS.

When you read the documentation for [JWE](https://tools.ietf.org/html/rfc7516), you will quickly realize [JWE](https://tools.ietf.org/html/rfc7516) can be used with RSA (Rivest–Shamir–Adleman) encryption. RSA is an Asymmetrical encryption technique ( a Public and Private key ). But JWE does not include a Digital Signature Algorithm (DSA), like Pretty Good Privacy (PGP) or GnuPG.

Therefore a need for JWS is called for, Digital Signature Validation. 

## Proof of Concept Requirements

This requires [Node JS version 12](https://nodejs.org/en/download/) implementation with OpenSSL 1.0.1g 7 Apr 2014. It is version specific, because the Crypto API in NodeJS is aggressively under development and significantly changes. 

A little bit of a Layout...

```
JWS [
	JWE [ Message ] <- encrypted with the Public Key of the Receiver
] Signed with the Private Key of the Sender 
```

Because the JWS is signed with the Private Key of the Sender, the Receiver must have the Public Key of the Sender to validate the signature. 

This means, there needs to be an exchange of Public Keys.

## Links I have found helpful

* [My Favorite Examples of JWT and JWE Compact Serialization](https://medium.facilelogin.com/jwt-jws-and-jwe-for-not-so-dummies-b63310d201a3)
* [JSON Web Encryption (JWE) Specification](https://tools.ietf.org/html/rfc7516)
* [JSON Web Signature (JWS) Specification](https://tools.ietf.org/html/rfc7515)
* [Great Examples of 101 Encrypting](https://coolaj86.com/articles/asymmetric-public--private-key-encryption-in-node-js/)
* [OpenSSL commands](https://www.freecodecamp.org/news/openssl-command-cheatsheet-b441be1e8c4a/)
* [Could be good](https://openid.net/specs/draft-jones-json-web-encryption-02.html)
* [Further reading](https://coolaj86.com/articles/asymmetric-public--private-key-encryption-in-node-js/)

## Common Terms

``RSA`` - RSA is a public-key crypto system and is widely used for secure data transmission. When generated it has both a private key and public key embedded in the Base64 encoded string.

``X.509`` - X.509 is a standard defining the format of public key certificates. Used commonly by TLS/SSl because of a PKI which can be used to assert the ownership of the Certificate.

``PKI`` - Public Key Infrastructure is a format for authenticating certificates.

``IV`` - Initial Vector is not commonly used with RSA Encryption. In cipher-block chaining mode (CBC mode), the IV must, in addition to being unique, be unpredictable at encryption time.

``AES`` - AES Encryption, on the other hand, in some modes, for instance CBC or CFB uses IV. These is because AES is a Block Cipher Mode of Operation .

``AAD`` - Additional Authenticated Data

``CEK`` - Content Encryption Key

``JWE Auth Tag`` - A value resulting from authenticated encryption of the plaintext with Additional Authenticated Data (AAD).
      
## Understanding JWS format 

A JWS payload is a set of 3 base64url encoded sections. Each section ( like JWT ) is separated by period. The purpose is to transmit a message with a digital signature in a standard format suitable for JSON.

For your reference, we will use this JWS and break down each section.

``
eyJhbGciOiJSU0EtU0hBMjU2In0.eyJtc2ciOiJoZWxsbyJ9.TuVQ6y60_bP2yoFLqrgrbGbYHJ1_ptw3rsbSTG7BBs2-KqWzRkRQw8iRlNa3ComyKmcy5rQdewJPdv1EJal9N9dFW-1peUlLw9iApDOBmiRsj5l16AJ9DgtnVI-8eXskUC_YxG-mVV8g72JgmNea4MMzHsak5qnWGdiDgYfp7I5CN3iqvWH3EVax8K9XKBjkw-uxzVDUAkjySFAYznJyyJDMfcJmjHE4pYbWkit1vBTeZFVn0M7JWjmuUDiMP6tCngJ3_FONXczmp9nKldHb_sd2Dha7YFtiiD5y7CVFmn53mWdo-ZXBDYqmMgstocL-yBjqkoYAnEzfw6LiBRP2qA
``

### Section One - JOSE

This first value is a base 64 encoded clear text UTF8 string that is the JOSE header ( a JSON object ) which describes the encryption for the KEY. Refer to the [JOSE format](#JOSE-format) section for a list of possible values, the actual valid values are based on the use of either JWE or JWS.

```eyJhbGciOiJSU0EtU0hBMjU2In0```

``JSON
{ "alg" : "RSA-SHA256" }
``

### Message Section

This second value is again a base 64 encoded UTF8 string. * NOT ENCRYPTED *

```eyJtc2ciOiJoZWxsbyJ9```

``JSON
{ "msg" : "hello" }
``

### Signature

The Last section is the base 64 encoded Signature ( based on the alg ). In this case, we are using the private key to digitally sign the payload and sharing the public key so people can verify it.

``TuVQ6y60_bP2yoFLqrgrbGbYHJ1_ptw3rsbSTG7BBs2-KqWzRkRQw8iRlNa3ComyKmcy5rQdewJPdv1EJal9N9dFW-1peUlLw9iApDOBmiRsj5l16AJ9DgtnVI-8eXskUC_YxG-mVV8g72JgmNea4MMzHsak5qnWGdiDgYfp7I5CN3iqvWH3EVax8K9XKBjkw-uxzVDUAkjySFAYznJyyJDMfcJmjHE4pYbWkit1vBTeZFVn0M7JWjmuUDiMP6tCngJ3_FONXczmp9nKldHb_sd2Dha7YFtiiD5y7CVFmn53mWdo-ZXBDYqmMgstocL-yBjqkoYAnEzfw6LiBRP2qA``
     
## Understanding JWE format

A JWE payload is a set of 5 base64url encoded sections. Each section ( like JWT ) is separated by period. The purpose is to transmit Encrypted data in a standard format suitable for JSON.

For your reference, we will use this JWE and break down each section.

```
N0IyMjYxNkM2NzIyM0EyMjUyNTM0MTJENEY0MTQ1NTAyRDMyMzUzNjIyMkMyMjY1NkU2MzIyM0EyMjQxMzIzNTM2NDc0MzREMjI3RA.M0VFQzY1QTdGRTlDOTJEQzg4OTc2RTk5RjU4MkYwMjZBNEEyNzIwNkVDNDU3QUJERjA4MDA4MjVBOUJBRDVBRDVDQTFEMTk2NTIzMzgwOTdFRDBBMjQ4N0VBNjZCMjI3REE1RjUzOUI5MDYyQjFGOTk3NERENUU2MjY0QkZFN0I0OTIwQUFCNkNCMDE2ODJCQjQxOEQ5RTIxMEY0MTRDQzA1RDI5NjdBN0UyNjNFQzgyRjlFMzI3NzM3RUY5QjM0MDgxQUI4MzQ1MENGOUQ4QzZCQkFFN0U3REQ0MTJBQUU5RTVDQUY4RjgxNDZBOEU2QjYyRkY0NjI0REM0RkJGMEY0MTIzQTg1QzY2RjhFQzExN0QwMjdGNTIzOTAyMDBERUEyOEY4QjNDNDM1NzU3MzMwNUZFRjVFNzExQ0Q5OEJFMzBGQjJDRDlENTM5MUYwNUZEQTE1OUJGMjU3QkZBODk1OTZDRjQxQzc2MEY2OUI3QTg1Q0RCQkYyRDdENzRGNkU4MzlDNkY1MEFFNkRDQjAzMUMyQTMyRjZDRkEyNkU2ODVFMkZBQkI0NThBM0FBMjgwRUJFQUJFRjI1MEJFQUJCMTYxMkFGMDMzRDk4MTFDOEJEODdENTU2M0QyRTcyNThGMkFEQUUzRDIzNUVGMzI4RDYwQTAzRDkyQkZBNjY.NTUzQzUwQjJFOUQ4RDM5QTFDQTgzQzc2MjE4Q0EyRThCNTY3NTgwMTNDM0EzQjMzNkQxNUM5RUIxQzc4Nzc5OQ.ODUyM0E2NTUyNDM2RkI5MjYyQjY0ODgyMjQ1N0Q3MDZCMUFBQzgxNTExRDVGM0MwMjkzQjk1NkExOTNDQURCM0REOUU4MDg0NTk1NUZFNDA1NzQ0MjQxRThBMTM2MDEwQTQ4NzQyRTlBOEU1QzI3NjY4Mjg2NjFEMDhCRTUyRUJBNkMwQjEwRTk5NDU3MDNDNTNFMTgzRUI0RDZDNUY2RjNBQTU1RTM4.QTNEQjM2REI3NTBDQzc1REJFODlDOEVBOTA1RDZBRkY
```

### Section One - JOSE

This first value is a base 64 encoded clear text UTF8 string that is the JOSE header ( a JSON object ) which describes the encryption for the KEY and the Content Encryption. Refer to the [JOSE format](#JOSE-format) section for a list of possible values.

```N0IyMjYxNkM2NzIyM0EyMjUyNTM0MTJENEY0MTQ1NTAyRDMyMzUzNjIyMkMyMjY1NkU2MzIyM0EyMjQxMzIzNTM2NDc0MzREMjI3RA```

### Section Two - CEK

This second value is again a base 64 encoded UTF8 string which may or may not contain a key. This key is called the Content Encryption Key ( CEK ) if present, it is used to encrypted the content. The encryption schema is described in the JOSE header and is based on the agreed upon Key Format see [Understanding Content Encryption Key Format](#Understanding-Content-Encryption-Key-Format). When the Key format is `Key Encryption` ( which is the case for this example ) the key is a symmetrical key and will be random per request and will be encrypted with the the private asymmetrical key.

```M0VFQzY1QTdGRTlDOTJEQzg4OTc2RTk5RjU4MkYwMjZBNEEyNzIwNkVDNDU3QUJERjA4MDA4MjVBOUJBRDVBRDVDQTFEMTk2NTIzMzgwOTdFRDBBMjQ4N0VBNjZCMjI3REE1RjUzOUI5MDYyQjFGOTk3NERENUU2MjY0QkZFN0I0OTIwQUFCNkNCMDE2ODJCQjQxOEQ5RTIxMEY0MTRDQzA1RDI5NjdBN0UyNjNFQzgyRjlFMzI3NzM3RUY5QjM0MDgxQUI4MzQ1MENGOUQ4QzZCQkFFN0U3REQ0MTJBQUU5RTVDQUY4RjgxNDZBOEU2QjYyRkY0NjI0REM0RkJGMEY0MTIzQTg1QzY2RjhFQzExN0QwMjdGNTIzOTAyMDBERUEyOEY4QjNDNDM1NzU3MzMwNUZFRjVFNzExQ0Q5OEJFMzBGQjJDRDlENTM5MUYwNUZEQTE1OUJGMjU3QkZBODk1OTZDRjQxQzc2MEY2OUI3QTg1Q0RCQkYyRDdENzRGNkU4MzlDNkY1MEFFNkRDQjAzMUMyQTMyRjZDRkEyNkU2ODVFMkZBQkI0NThBM0FBMjgwRUJFQUJFRjI1MEJFQUJCMTYxMkFGMDMzRDk4MTFDOEJEODdENTU2M0QyRTcyNThGMkFEQUUzRDIzNUVGMzI4RDYwQTAzRDkyQkZBNjY```

There are a couple of ways the CEK can be encrypted, they are listed here. For this purpose we will use the ``Key Encryption``.

* `Key Encryption` - The CEK value is encrypted to the intended recipient using an asymmetric encryption algorithm
* `Key Wrapping` - The CEK value is encrypted to the intended recipient using a symmetric key wrapping algorithm
* `Direct Key Agreement` - The key agreement algorithm is used to agree upon the CEK value
* `Key Agreement with Key Wrapping` - A Key Management Mode in which a key agreement algorithm is used to agree upon a symmetric key used to encrypt the CEK value to the intended recipient using a symmetric key wrapping algorithm
* `Direct Encryption algorithm` - The CEK value used is the secret symmetric key value shared between the parties.

### Section Three - IV

This third value, is again a base 64 encoded string which is the Initialization Vector ( if applicable to the encryption method ). An IV is a fixed size random value used to ensure the cipher text is never the same when the underlining value is repeated across encryption ( a known security flaw which undermines the security ) 

``NTUzQzUwQjJFOUQ4RDM5QTFDQTgzQzc2MjE4Q0EyRThCNTY3NTgwMTNDM0EzQjMzNkQxNUM5RUIxQzc4Nzc5OQ`` 
 
### Section Four - Content
 
This fourth value, is again a base 64 encoded string which for the purpose of this demonstration is the symmetrically encrypted value ( the key being the asymmetrical encrypted CEK which is a symmetrical key and based on the Key format `Key Encryption` ) 

``ODUyM0E2NTUyNDM2RkI5MjYyQjY0ODgyMjQ1N0Q3MDZCMUFBQzgxNTExRDVGM0MwMjkzQjk1NkExOTNDQURCM0REOUU4MDg0NTk1NUZFNDA1NzQ0MjQxRThBMTM2MDEwQTQ4NzQyRTlBOEU1QzI3NjY4Mjg2NjFEMDhCRTUyRUJBNkMwQjEwRTk5NDU3MDNDNTNFMTgzRUI0RDZDNUY2RjNBQTU1RTM4``

### Section Five - Auth Tag

This last part ( the fifth value ), is again a base 64 encoded string called the Auth Tag. It incorporates the message authentication code which is the AAD ( Additional Authenticated Data ) needed to validate the data. According to the specification, should be the Jose Header.

``QTNEQjM2REI3NTBDQzc1REJFODlDOEVBOTA1RDZBRkY``
 
## JOSE format

For this purpose we will use the Key format `Key Encryption`. This means the encrypted content will be encrypted by `A256GCM` and the Key will be `RSA-OAEP-256`. The sender, will take the Public Key and encrypt the Private Key ( this is called the CEK ). the private key will encrypt the content. The JOSE format changes slightly between JWS and JWE, you will need to refer to the RFC.

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

## Testing

There are two sets of tests, one for JWE and one for JWS. All the tests, use auto generated RSA.

## Notes

JWE, can be used to encrypt any mime type ( which can be declared via [cty](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10) in the JOSE header ). However, for simplicity and illustration, these examples assume the content is a UTF-8 String of JSON. 

Furthermore, in this example, I use an optional GZIP for the [zip](https://tools.ietf.org/html/rfc7516#section-4.1.3) declaration.

## TODO

* Try to understand a get the [kid](https://tools.ietf.org/html/rfc7516#section-4.1.6) or [jwk](https://tools.ietf.org/html/rfc7516#section-4.1.5) working 

* I noticed that the `oaepHash` is not working for and is defaulted to SHA1... I dont like this. I need to find out why.

* Still not sure if I need to ASCII encode JWE and JWS generated token..

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
