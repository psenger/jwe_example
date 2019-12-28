import {
    constants,
    createCipheriv,
    createDecipheriv,
    KeyLike,
    privateDecrypt,
    publicEncrypt,
    randomBytes,
    RsaPrivateKey,
    RsaPublicKey,
    CipherGCM
} from "crypto";

import { gunzipSync, gzipSync, constants as zConstants } from 'zlib';
import {stringify} from "querystring";

enum ZIP {
    GZIP = "GZIP"
}
interface JOSE {
    enc: string;
    alg: string;
    zip?: ZIP
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

    static base64url(value: string): string {
        return Buffer
            .from(value, 'utf8')
            .toString('base64')
            .replace(/=/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_');
    }

    static lru46esab (value: string): string {
        return Buffer.from(value,'base64')
            .toString('utf8')
            .replace('-', '+')
            .replace('_', '/');
    }

    private AsymmetricEncryptOffPublicKey ( value: Buffer ): string {
        // If key ( A PEM encoded public key ) is a string, it is treated as the
        // key with no passphrase and will use RSA_PKCS1_OAEP_PADDING.
        // We are passing as KeyLike Typescript object, which means
        // we need to declare the padding.
        const key: RsaPublicKey = {
            key: this.publicKey,
            padding: constants.RSA_PKCS1_OAEP_PADDING
        };
        // return publicEncrypt( key, value ).toString('hex').toUpperCase();
        return publicEncrypt( key, value ).toString('hex').toUpperCase();
    }

    private AsymmetricDecryptOffPrivateKey ( value: string ): Buffer {
        const key: KeyLike = this.privateKey;
        const private_key: RsaPrivateKey = {
            key,
            passphrase: this.passphrase,
            oaepHash: 'sha256',
            padding: constants.RSA_PKCS1_OAEP_PADDING
        };
        return privateDecrypt( private_key, Buffer.from( value, 'hex' ) );
    }

    /**
     * https://tools.ietf.org/html/rfc7516
     */
    public encrypt ( value: string, options?: any ): string {
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
        const joseStr : string = Buffer.from( JSON.stringify( jose ), 'utf8').toString('hex').toUpperCase();
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
        const cipher: CipherGCM = createCipheriv(  'aes-256-gcm', cek, iv );
        let cipherText: Buffer;
        if ( options && options.zip && options.zip === ZIP.GZIP ) {
            const b : Buffer = gzipSync( value, {
                level: zConstants.Z_BEST_COMPRESSION
            } );
            cipherText = cipher.update( b );
        } else {
            cipherText = cipher.update( value );
        }
        const cipherTextHex = Buffer.concat([ cipherText, cipher.final() ] ).toString('hex').toUpperCase();
        const tag: Buffer = cipher.getAuthTag();
        const cekStr : string = this.AsymmetricEncryptOffPublicKey( cek ); // we asymmetrically encrypt the key with the users Public Key.
        const ivStr : string = iv.toString('hex').toUpperCase();// IV and Tag are not encrypted with Asymmetric encryption
        const tagStr: string = tag.toString('hex').toUpperCase();
        return `${ JWE.base64url( joseStr ) }.${ JWE.base64url( cekStr ) }.${ JWE.base64url( ivStr ) }.${ JWE.base64url( cipherTextHex ) }.${ JWE.base64url( tagStr ) }`
    }

    public decrypt ( payload: string ): string {
        let joseStr: string;
        let cekStr: string;
        let ivStr: string;
        let cipherTextStr: string;
        let tagStr: string;
        [joseStr, cekStr, ivStr, cipherTextStr, tagStr] = payload.split('.').map(JWE.lru46esab);
        let jose: JOSE = JSON.parse( Buffer.from( joseStr, 'hex').toString('utf8'));
        if ( jose.alg !== 'RSA-OAEP-256' ) {
            throw new Error('Unsupported "alg" detected in JOSE. currently only "RSA-OAEP-256" supported');
        }
        if ( jose.enc !== 'A256GCM' ) {
            throw new Error('Unsupported "enc" detected in JOSE. currently only "A256GCM" supported');
        }
        if ( jose.zip && jose.zip !== ZIP.GZIP ) {
            throw new Error(`Unsupported "zip" detected in JOSE. currently only "${ZIP.GZIP}" supported`);
        }
        const iv: Buffer = Buffer.from(ivStr, 'hex');
        const cek: Buffer = this.AsymmetricDecryptOffPrivateKey( cekStr );
        const decipher = createDecipheriv( 'aes-256-gcm', cek, iv );
        const tag: Buffer = Buffer.from( tagStr, 'hex' );
        decipher.setAuthTag(tag);
        let cipherText: Buffer = decipher.update( Buffer.from( cipherTextStr, 'hex' ) );
        if ( jose.zip && jose.zip === ZIP.GZIP ) {
            cipherText = gunzipSync( cipherText , {
                level: zConstants.Z_BEST_COMPRESSION
            } )
        } else {

        }
        return cipherText.toString('utf8');
    }

}
