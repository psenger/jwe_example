"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var crypto_1 = require("crypto");
var zlib_1 = require("zlib");
var ZIP;
(function (ZIP) {
    ZIP["GZIP"] = "GZIP";
})(ZIP = exports.ZIP || (exports.ZIP = {}));
var MEDIA_TYPES;
(function (MEDIA_TYPES) {
    MEDIA_TYPES["JSON"] = "json";
})(MEDIA_TYPES = exports.MEDIA_TYPES || (exports.MEDIA_TYPES = {}));
/**
 * a safer way to do toString on an object
 * @param obj
 */
var toSafeString = function toSafeString(obj) {
    if (typeof obj === 'string')
        return obj;
    if (typeof obj === 'number' || Buffer.isBuffer(obj))
        return obj.toString();
    return JSON.stringify(obj);
};
/**
 * Base 64 URL encode
 * @param value
 */
var base64url = function base64url(value) {
    return value.toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
};
/**
 * Base 64 URL decode
 * @param value
 */
var lru46esab = function lru46esab(value) {
    return Buffer.from(value.replace('-', '+').replace('_', '/'), 'base64');
};
/**
 * Is the thing an object? might be better ways of doing this with ES6... just needed to get it done.
 * @param thing
 */
var isObject = function isObject(thing) {
    return Object.prototype.toString.call(thing) === '[object Object]';
};
/**
 * Safe JSON parse...
 * @param thing
 */
var safeJsonParse = function safeJsonParse(thing) {
    if (isObject(thing))
        return thing;
    try {
        return JSON.parse(thing);
    }
    catch (e) {
        return undefined;
    }
};
/**
 * Asymmetric Encrypt With Public Key
 * @param value
 * @param publicKey
 */
var AsymmetricEncryptWithPublicKey = function AsymmetricEncryptWithPublicKey(value, publicKey) {
    // If key ( A PEM encoded public key ) is a string, it is treated as the
    // key with no passphrase and will use RSA_PKCS1_OAEP_PADDING.
    // We are passing as KeyLike Typescript object, which means
    // we need to declare the padding.
    var public_key = {
        key: publicKey,
        padding: crypto_1.constants.RSA_PKCS1_OAEP_PADDING
    };
    return crypto_1.publicEncrypt(public_key, value);
};
/**
 * Asymmetric Decrypt With Private Key
 * @param value
 * @param privateKey
 * @param passphrase
 */
var AsymmetricDecryptWithPrivateKey = function AsymmetricDecryptWithPrivateKey(value, privateKey, passphrase) {
    var private_key = {
        key: privateKey,
        passphrase: passphrase,
        // @todo: Still trying to establish why this is not working.
        // oaepLabel:  https://github.com/nodejs/help/issues/1726
        // oaepHash: 'sha256', // this does not appear to work on Mac OSX with OpenSSL 1.0.1g 7 Apr 2014 or OpenSSL 1.1.1d  10 Sep 2019 ( via Brew )
        padding: crypto_1.constants.RSA_PKCS1_OAEP_PADDING
    };
    return crypto_1.privateDecrypt(private_key, value);
};
/**
 * JWE Decrypt
 *
 * When decrypting, particular care must be taken not to allow the JWE recipient to be used as an oracle for
 * decrypting messages.  RFC 3218 should be consulted for specific countermeasures to attacks on RSAES-PKCS1-v1_5.
 *
 * An attacker might modify the contents of the "alg" Header Parameter from "RSA-OAEP" to "RSA1_5" in order to
 * generate a formatting error that can be detected and used to recover the CEK even if RSAES-OAEP was used to
 * encrypt the CEK.  It is therefore particularly important to report all formatting errors to the CEK, Additional
 * Authenticated Data, or ciphertext as a single error when the encrypted content is rejected.
 *
 * Additionally, this type of attack can be prevented by restricting the use of a key to a limited set of
 * algorithms -- usually one.  This means, for instance, that if the key is marked as being for "RSA-OAEP" only,
 * any attempt to decrypt a message using the "RSA1_5" algorithm with that key should fail immediately due to
 * invalid use of the key.
 *
 * @param payload
 * @param privateKey
 * @param passphrase
 */
var decrypt = function decrypt(payload, privateKey, passphrase) {
    var _a;
    try {
        var joseStr = void 0;
        var cekStr = void 0;
        var ivStr = void 0;
        var cipherTextStr = void 0;
        var tagStr = void 0;
        /**
         * JOSE - Javascript Object Signing and Encryption Header
         * CEK - Content Encryption Key ( Asymmetrically encrypted with the )
         * IV - Initialization Vector
         * cipherText - The Symmetrically encrypted payload of a UTF-8 String, with the mime type identified as `cty` in the JOSE
         * tag - Auth tag is the message authentication code (MAC) calculated during the encryption
         */
        _a = payload.split('.'), joseStr = _a[0], cekStr = _a[1], ivStr = _a[2], cipherTextStr = _a[3], tagStr = _a[4];
        // @TODO: need to exit here, if there are any values equal to null
        var jose = safeJsonParse(Buffer.from(joseStr, 'base64').toString('utf8'));
        if (jose.alg !== 'RSA-OAEP-256') {
            throw new Error('Unsupported "alg" detected in JOSE. currently only "RSA-OAEP-256" supported');
        }
        if (jose.enc !== 'A256GCM') {
            throw new Error('Unsupported "enc" detected in JOSE. currently only "A256GCM" supported');
        }
        if (jose.zip && jose.zip !== ZIP.GZIP) {
            throw new Error("Unsupported \"zip\" detected in JOSE. currently only \"" + ZIP.GZIP + "\" supported");
        }
        var cek = AsymmetricDecryptWithPrivateKey(lru46esab(cekStr), privateKey, passphrase);
        var decipher = crypto_1.createDecipheriv('aes-256-gcm', cek, lru46esab(ivStr));
        /**
         * When using an authenticated encryption mode ( like GCM ),
         * the decipher.setAuthTag() method is used to pass in the received authentication tag. If no tag is
         * provided, or if the cipher text has been tampered with, decipher.final() will throw, indicating
         * that the cipher text should be discarded due to failed authentication. If the tag length is
         * invalid according to NIST SP 800-38D or does not match the value of the authTagLength option,
         * decipher.setAuthTag() will throw an error.
         *
         * The decipher.setAuthTag() method must be called before decipher.final() and can only be called once.
         */
        decipher.setAuthTag(lru46esab(tagStr));
        decipher.setAAD(Buffer.from(toSafeString(jose), 'utf8'));
        var text = Buffer.concat([decipher.update(lru46esab(cipherTextStr)), decipher.final()]);
        if (jose.zip && jose.zip === ZIP.GZIP) {
            return zlib_1.gunzipSync(text, { level: zlib_1.constants.Z_BEST_COMPRESSION }).toString('utf8');
        }
        return text.toString('utf8');
    }
    catch (e) {
        console.error(e);
        throw new Error('A decryption error has occurred. refer to the logs for more details.');
    }
};
var encrypt = function encrypt(value, publicKey, options) {
    // RSA-OAEP-256 - RSAES OAEP using SHA-256 and MGF1 with SHA-256
    //  @see https://www.rfc-editor.org/rfc/rfc7518#section-4.3
    var alg = 'RSA-OAEP-256';
    // AES 256 GCM - encryption of the content.
    var enc = 'A256GCM';
    /**
     * Javascript Object Signing and Encryption (JOSE ) - describe the encryption
     * applied to the plaintext and optionally additional properties of the JWE.
     */
    var jose = { alg: alg, enc: enc };
    /**
     * Optional the body zip type, should be omitted from the JOSE to indicate no compression
     */
    if (options && options.zip) {
        if (options.zip !== ZIP.GZIP) {
            throw new Error("Unsupported \"zip\" detected in JOSE. currently only \"" + ZIP.GZIP + "\" supported");
        }
        jose.zip = ZIP.GZIP;
    }
    if (options && options.cty !== MEDIA_TYPES.JSON) {
        throw new Error("Unsupported \"cty\" detected in JOSE. currently only \"" + MEDIA_TYPES.JSON + "\" supported");
    }
    jose.cty = MEDIA_TYPES.JSON;
    /**
     * Content Encryption Key (CEK) - ( this is the symmetrical key, which will later be
     * encrypted asymmetrically ) A new symmetric key generated to encrypt the Plaintext
     * for the recipient to produce the Ciphertext, which is encrypted to the recipient as
     * the JWE Encrypted Key. 32 Bytes = 256 bits
     */
    var cek = crypto_1.randomBytes(32);
    if (cek.length !== 32)
        throw new Error('AES Key Must be 256 bytes (32 characters)');
    /**
     * JWE Initialization Vector
     * The bit block size of the encryption algorithm dictates the
     * Byte size of the IV. eg: A128GCM is 128 Bits = 16 Bytes and 256 Bits would be 32
     */
    var iv = crypto_1.randomBytes(32);
    /**
     * aes-256-cgm - Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM)
     * AES-GCM is a more secure cipher than AES-CBC, because AES-CBC, operates by XOR'ing
     * each block with the previous block and cannot be written in parallel and
     * Initialization Vector is required because AES is a Block Encryption method.
     * AES is a block cipher mode type of encryption
     */
    var cipher = crypto_1.createCipheriv('aes-256-gcm', cek, iv);
    /**
     * When using an authenticated encryption mode (GCM, CCM and OCB are currently supported), the cipher.setAAD()
     * method sets the value used for the additional authenticated data (AAD) input parameter.
     *
     * The options argument is optional for GCM and OCB. When using CCM, the plaintextLength option must be
     * specified and its value must match the length of the plaintext in bytes. See CCM mode.
     *
     * The cipher.setAAD() method must be called before cipher.update().
     */
    cipher.setAAD(Buffer.from(toSafeString(jose), 'utf8'));
    var content;
    if (options && options.zip && options.zip === ZIP.GZIP) {
        content = cipher.update(zlib_1.gzipSync(value, {
            level: zlib_1.constants.Z_BEST_COMPRESSION
        }));
    }
    else {
        content = cipher.update(value);
    }
    var cipherText = Buffer.concat([content, cipher.final()]);
    /**
     * When using an authenticated encryption mode ( like GCM ), cipher.getAuthTag() method
     * returns a Buffer containing the authentication tag that has been computed from the given data.
     *
     * Message Authentication Code (MAC)
     *
     * The cipher.getAuthTag() method should only be called after encryption has been completed using the
     * cipher.final() method.
     */
    var tag = cipher.getAuthTag();
    var ecek = AsymmetricEncryptWithPublicKey(cek, publicKey); // we asymmetrically encrypt the key with the users Public Key.
    // @todo: I think it would be best, if we make sure the output is ASCII
    // Buffer.from( '').toString('ascii')
    return base64url(Buffer.from(toSafeString(jose), 'utf8')) + "." + base64url(ecek) + "." + base64url(iv) + "." + base64url(cipherText) + "." + base64url(tag);
};
/**
 * Generate a JWS Token
 * @param value
 * @param privateKey
 */
var encode = function encode(value, privateKey) {
    // while HMAC-SHA256 is by far better than RSA-SHA256. It would require a private key by both parties. Therefore,
    // we will use RSA and exchange Public Keys.
    var signature = crypto_1.createSign('RSA-SHA256');
    /**
     * Javascript Object Signing and Encryption (JOSE ) - describe the encryption
     * applied to the plaintext and optionally additional properties of the JWE.
     */
    var jose = { alg: 'RSA-SHA256' };
    var joseAndValue = base64url(Buffer.from(toSafeString(jose), 'utf8')) + "." + base64url(Buffer.from(value, 'utf8'));
    /**
     * Compute the JWS Signature with RSA-SHA256
     *
     * ASCII(   BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload)   )
     *
     * The "alg" (algorithm) Header Parameter
     * MUST be present in the JOSE Header, with the algorithm value
     * accurately representing the algorithm used to construct the JWS
     * Signature.
     */
    signature.write(joseAndValue);
    signature.end();
    var base64Signature = signature.sign(privateKey, 'base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
    return joseAndValue + "." + base64Signature;
};
/**
 * Verify the Payload is signed correctly.
 * @param jwsPayload
 * @param publicKey
 */
var verify = function verify(jwsPayload, publicKey) {
    var _a = jwsPayload.split('.'), joseStr = _a[0], message = _a[1], sig = _a[2];
    var jose = JSON.parse(lru46esab(joseStr).toString('utf8'));
    if (jose && jose.alg && jose.alg !== 'RSA-SHA256') {
        throw new Error("Unsupported \"alg\" detected in JOSE. currently only \"RSA-SHA256\" supported");
    }
    var verify = crypto_1.createVerify(jose.alg);
    verify.write(joseStr + "." + message);
    verify.end();
    return verify.verify(publicKey, sig, 'base64');
};
/**
 * Extract the message from the JwsPayload.
 * @param jwsPayload
 */
var decode = function decode(jwsPayload) {
    var _a = jwsPayload.split('.'), message = _a[1];
    return lru46esab(message).toString('utf8');
};
exports.JWE = {
    encrypt: encrypt,
    decrypt: decrypt
};
exports.JWS = {
    decode: decode,
    encode: encode,
    verify: verify
};
