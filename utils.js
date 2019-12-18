const crypto = require('crypto');

module.exports = ( passphrase, publicKey, privateKey ) => {

    const base64url = (string, encoding) => {
        return Buffer
            .from(string, encoding)
            .toString('base64')
            .replace(/=/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_');
    };

    const lru46esab = (string) => {
        return Buffer.from(string,'base64')
            .toString('utf8')
            .replace('-', '+')
            .replace('_', '/');
    };

    const AsymmetricEncryptOffPublicKey = ( text ) => {
        return crypto.publicEncrypt( publicKey, Buffer.from( text, 'utf8' ) ).toString('hex');
    };

    const AsymmetricDecryptOffPrivateKey = ( text ) => {
        return crypto.privateDecrypt( {
            key: privateKey,
            passphrase,
        }, Buffer.from( text, 'hex' ) );
    };

    /**
     * https://tools.ietf.org/html/rfc7516
     */
    const encrypt = ( text ) => {
        let jose = Buffer.from( JSON.stringify({ alg: 'RSA-OAEP', enc: 'A256GCM' } ), 'utf8' ).toString('hex');
        // Content Encryption Key (CEK) - ( this is the symmetrical key, which will later be
        // encrypted asymmetrically ) A new symmetric key generated to encrypt the Plaintext
        // for the recipient to produce the Ciphertext, which is encrypted to the recipient as
        // the JWE Encrypted Key. 32 Bytes = 256 bits
        let cek = crypto.randomBytes(32);
        if ( cek.length !== 32 ) throw new Error('AES Key Must be 256 bytes (32 characters)');
        // JWE Initialization Vector
        // The bit block size of the encryption algorithm dictates the
        // Byte size of the IV. eg: A128GCM is 128 Bits = 16 Bytes and 256 Bits would be 32
        let iv = crypto.randomBytes(32 );
        // aes-256-cgm - Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM)
        // AES-GCM is a more secure cipher than AES-CBC, because AES-CBC, operates by XOR'ing
        // each block with the previous block and cannot be written in parallel and
        // Initialization Vector is required because AES is a Block Encryption method.
        // AES is a block cipher mode type of encryption
        const cipher = crypto.createCipheriv(  'aes-256-gcm', cek, iv );
        let cipherText = cipher.update( text );
        cipherText = Buffer.concat([ cipherText, cipher.final() ] ).toString('hex');
        let tag = cipher.getAuthTag();
        cek = AsymmetricEncryptOffPublicKey( cek ); // we asymmetrically encrypt the key with the users Public Key.
        iv = iv.toString('hex'); // IV and Tag are not encrypted with Asymmetric encryption
        tag = tag.toString('hex');
        return `${ base64url( jose ) }.${ base64url( cek ) }.${ base64url( iv ) }.${ base64url( cipherText ) }.${ base64url( tag ) }`
    };

    const decrypt = ( payload ) => {
        let [jose,cek,iv,cipherText,tag] = payload.split('.').map(lru46esab);
        jose = JSON.parse( Buffer.from( jose, 'hex' ).toString('utf8') );
        if ( jose.alg !== 'RSA-OAEP' ) {
            throw new Error('Unsupported alg detected in JOSE. currently only RSA-OAEP supported');
        }
        if ( jose.enc !== 'A256GCM' ) {
            throw new Error('Unsupported enc detected in JOSE. currently only A256GCM supported');
        }
        cek = AsymmetricDecryptOffPrivateKey( cek );
        const decipher = crypto.createDecipheriv('aes-256-gcm', cek, Buffer.from( iv, 'hex' ) );
        decipher.setAuthTag( Buffer.from( tag, 'hex' ) );
        let text = decipher.update( Buffer.from( cipherText, 'hex' ) );
        text = Buffer.concat([ text, decipher.final() ] );
        return text.toString('utf8');
    };

    return {
        encrypt,
        decrypt,
    };
};
