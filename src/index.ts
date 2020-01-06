import {
    CipherGCM,
    constants,
    createCipheriv,
    createDecipheriv,
    DecipherGCM,
    KeyLike,
    privateDecrypt,
    publicEncrypt,
    randomBytes,
    RsaPrivateKey,
    RsaPublicKey
} from "crypto";
import {constants as zConstants, gunzipSync, gzipSync} from 'zlib';

export enum ZIP {
    GZIP = "GZIP"
}
export interface JOSE {
    enc: string;
    alg: string;
    zip?: ZIP;
    cty?: MEDIA_TYPES;
}

export enum MEDIA_TYPES {
    JSON = 'json', // at this time it only makes sense to support application/json.
}

export interface OPTIONS {
    zip?: ZIP,
    cty: MEDIA_TYPES
}

export default class JWE {

    passphrase: string;
    publicKey: Buffer;
    privateKey: Buffer;

    // RSA-OAEP-256 - RSAES OAEP using SHA-256 and MGF1 with SHA-256
    //  @see https://www.rfc-editor.org/rfc/rfc7518#section-4.3
    static alg = 'RSA-OAEP-256';
    // AES 256 GCM - encryption of the content.
    static enc = 'A256GCM';

    /**
     * @param passphrase - for the Private Key
     * @param publicKey
     * @param privateKey
     */
    constructor( passphrase: string, publicKey: Buffer, privateKey: Buffer ) {
        this.passphrase = passphrase;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    static toSafeString(obj: any): string {
        if (typeof obj === 'string')
            return obj;
        if (typeof obj === 'number' || Buffer.isBuffer(obj))
            return obj.toString();
        return JSON.stringify(obj);
    };

    static base64url( value: Buffer ): string {
        return value.toString('base64')
            .replace(/=/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_');
    }

    static lru46esab ( value: string ): Buffer {
       return Buffer.from (
           value.replace('-', '+').replace('_', '/'),
           'base64'
       );
    }

    private AsymmetricEncryptOffPublicKey ( value: Buffer ): Buffer {
        // If key ( A PEM encoded public key ) is a string, it is treated as the
        // key with no passphrase and will use RSA_PKCS1_OAEP_PADDING.
        // We are passing as KeyLike Typescript object, which means
        // we need to declare the padding.
        const key: KeyLike = this.publicKey;
        const public_key: RsaPublicKey = {
            key,
            padding: constants.RSA_PKCS1_OAEP_PADDING
        };
        // return publicEncrypt( key, value ).toString('hex').toUpperCase();
        return publicEncrypt( public_key, value );//.toString('hex').toUpperCase();
    }

    private AsymmetricDecryptOffPrivateKey ( value: Buffer ): Buffer {
        try {
            const key: KeyLike = this.privateKey;
            const private_key: RsaPrivateKey = {
                key,
                passphrase: this.passphrase,
                // oaepHash: 'sha256', - this does not appear to work on Mac OSX with OpenSSL 1.0.1g 7 Apr 2014 or OpenSSL 1.1.1d  10 Sep 2019 ( via Brew )
                padding: constants.RSA_PKCS1_OAEP_PADDING
            };
            return privateDecrypt(private_key, value);
        } catch (e) {
            console.log(e);
            throw e;
        }
    }

    private isObject(thing: any) {
        return Object.prototype.toString.call(thing) === '[object Object]';
    }

    private safeJsonParse(thing: any) {
        if (this.isObject(thing))
            return thing;
        try { return JSON.parse(thing); }
        catch (e) { return undefined; }
    }

    /**
     * https://tools.ietf.org/html/rfc7516
     */
    public encrypt ( value: string, options: OPTIONS ): string {
        // Javascript Object Signing and Encryption (JOSE ) - describe the encryption
        // applied to the plaintext and optionally additional properties of the JWE.
        const jose: JOSE = { alg: JWE.alg, enc: JWE.enc };
        // Optional the body zip type, should be omitted from the JOSE to indicate no compression
        if ( options && options.zip ) {
            if ( options.zip !== ZIP.GZIP ) {
                throw new Error(`Unsupported "zip" detected in JOSE. currently only "${ZIP.GZIP}" supported`);
            }
            jose.zip = ZIP.GZIP;
        }
        if ( options.cty !== MEDIA_TYPES.JSON ) {
            throw new Error(`Unsupported "cty" detected in JOSE. currently only "${MEDIA_TYPES.JSON}" supported`);
        }
        jose.cty = MEDIA_TYPES.JSON;
        // Content Encryption Key (CEK) - ( this is the symmetrical key, which will later be
        // encrypted asymmetrically ) A new symmetric key generated to encrypt the Plaintext
        // for the recipient to produce the Ciphertext, which is encrypted to the recipient as
        // the JWE Encrypted Key. 32 Bytes = 256 bits
        const cek: Buffer = randomBytes(32);
        if ( cek.length !== 32 ) throw new Error('AES Key Must be 256 bytes (32 characters)');
        // JWE Initialization Vector
        // The bit block size of the encryption algorithm dictates the
        // Byte size of the IV. eg: A128GCM is 128 Bits = 16 Bytes and 256 Bits would be 32
        const iv: Buffer = randomBytes(32 );
        // aes-256-cgm - Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM)
        // AES-GCM is a more secure cipher than AES-CBC, because AES-CBC, operates by XOR'ing
        // each block with the previous block and cannot be written in parallel and
        // Initialization Vector is required because AES is a Block Encryption method.
        // AES is a block cipher mode type of encryption
        const CIPHER: CipherGCM = createCipheriv(  'aes-256-gcm', cek, iv );
        let content: Buffer;
        if ( options && options.zip && options.zip === ZIP.GZIP ) {
            content = CIPHER.update(
                gzipSync( value, {
                    level: zConstants.Z_BEST_COMPRESSION
                } )
            );
        } else {
            content = CIPHER.update( value );
        }
        const cipherText = Buffer.concat([ content, CIPHER.final() ] );
        const tag: Buffer = CIPHER.getAuthTag();
        const ecek : Buffer = this.AsymmetricEncryptOffPublicKey( cek ); // we asymmetrically encrypt the key with the users Public Key.

        return `${ JWE.base64url( Buffer.from( JWE.toSafeString( jose ),'utf8' ) ) }.${ JWE.base64url( ecek ) }.${ JWE.base64url( iv ) }.${ JWE.base64url( cipherText ) }.${ JWE.base64url( tag ) }`
    }

    public decrypt ( payload: string ): string {
        let joseStr: string;
        let cekStr: string;
        let ivStr: string;
        let cipherTextStr: string;
        let tagStr: string;
        [joseStr, cekStr, ivStr, cipherTextStr, tagStr] = payload.split('.');
        // @TODO: need to exit here, if there are any values equal to null
        let jose: JOSE = this.safeJsonParse( Buffer.from(joseStr, 'base64' ).toString( 'utf8' ) );
        if ( jose.alg !== 'RSA-OAEP-256' ) {
            throw new Error('Unsupported "alg" detected in JOSE. currently only "RSA-OAEP-256" supported');
        }
        if ( jose.enc !== 'A256GCM' ) {
            throw new Error('Unsupported "enc" detected in JOSE. currently only "A256GCM" supported');
        }
        if ( jose.zip && jose.zip !== ZIP.GZIP ) {
            throw new Error(`Unsupported "zip" detected in JOSE. currently only "${ZIP.GZIP}" supported`);
        }
        const cek: Buffer = this.AsymmetricDecryptOffPrivateKey( JWE.lru46esab( cekStr ) )
        const decipher: DecipherGCM = createDecipheriv( 'aes-256-gcm', cek, JWE.lru46esab( ivStr ) );
        decipher.setAuthTag( JWE.lru46esab( tagStr ) );
        let text: Buffer = decipher.update( JWE.lru46esab( cipherTextStr ) );
        if ( jose.zip && jose.zip === ZIP.GZIP ) {
            return gunzipSync(text, {level: zConstants.Z_BEST_COMPRESSION}).toString('utf8');
        }
        return text.toString('utf8');
    }

}
