const {generateKeyPairSync, randomBytes} = require('crypto');
const { JWE, JWS } = require('../dist/index');

const BuildAKey = () => {
    const passphrase = randomBytes(256).toString('hex');
    const {publicKey, privateKey} = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'pkcs1',
            format: 'pem',
        },
        privateKeyEncoding: {
            type: 'pkcs1',
            format: 'pem',
            cipher: 'aes-256-cbc',
            passphrase
        }
    });
    return {
        publicKey,
        privateKey,
        passphrase
    }
};

const originalMessage = require('./originalMessage.json');
describe('jwe_example',()=>{
    let SenderKeys = {
        passphrase: null,
        publicKey: null,
        privateKey: null
    };
    beforeAll(() => {
        SenderKeys = BuildAKey();
    });
    test('should make keys and passphrase', () => {
        expect(SenderKeys.passphrase).toBeTruthy();
        expect(SenderKeys.privateKey).toBeTruthy();
        expect(SenderKeys.passphrase).toBeTruthy();
    });
    describe('JWE', () => {
        test('Should work when zipped is not passed',()=>{
            const encryptedMessage = JWE.encrypt(JSON.stringify(originalMessage), SenderKeys.publicKey, { cty: 'json' });
            const decryptedMessage = JWE.decrypt(encryptedMessage, SenderKeys.privateKey, SenderKeys.passphrase );
            expect(JSON.stringify(originalMessage)).toEqual(decryptedMessage);
        });
        test('Should work when Zipped is passed',()=>{
            const encryptedMessage = JWE.encrypt(JSON.stringify(originalMessage), SenderKeys.publicKey, { zip: 'GZIP', cty: 'json' });
            const decryptedMessage = JWE.decrypt(encryptedMessage, SenderKeys.privateKey, SenderKeys.passphrase );
            expect(JSON.stringify(originalMessage)).toEqual(decryptedMessage);
        });
        test('should throw an error when the JOSE has been tampered with',()=>{
            const e = new Error('A decryption error has occurred. refer to the logs for more details.');
            const testFn = () => {
                let encryptedMessage = JWE.encrypt(JSON.stringify(originalMessage), SenderKeys.publicKey, { zip: 'GZIP', cty: 'json' });
                // tamper with the header.
                let [jose, cekStr, ivStr, cipherTextStr, tagStr] = encryptedMessage.split('.');
                let joseStr = JSON.parse(Buffer.from (
                    jose.replace('-', '+').replace('_', '/'),
                    'base64'
                ).toString('utf8'));
                joseStr['monkeyGo']='boom boom';
                joseStr = Buffer.from( JSON.stringify(joseStr), 'utf8' ).toString('base64')
                    .replace(/=/g, '')
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_');
                encryptedMessage = [joseStr, cekStr, ivStr, cipherTextStr, tagStr].join('.');
                JWE.decrypt(encryptedMessage, SenderKeys.privateKey, SenderKeys.passphrase );
            };
            expect(testFn).toThrow(e);
        })
    });
    describe('JWS', () => {
        test('should sign without any errors', () => {
            const jws = JWS.encode(JSON.stringify(originalMessage), {
                key: SenderKeys.privateKey,
                format: 'pem',
                type: 'pkcs1',
                passphrase: SenderKeys.passphrase
            });
            expect(jws).toBeTruthy();
            expect(jws.split('.').length).toEqual(3);
        });
        test('should sign and verify', () => {
            const senderA_SignedMessage = JWS.encode(JSON.stringify(originalMessage), {
                key: SenderKeys.privateKey,
                format: 'pem',
                type: 'pkcs1',
                passphrase: SenderKeys.passphrase
            });
            const answer = JWS.verify(senderA_SignedMessage, SenderKeys.publicKey);
            expect(answer).toBeTruthy();
        });
        test('should extract value from JWS', () => {
            const senderA_SignedMessage = JWS.encode(JSON.stringify(originalMessage), {
                key: SenderKeys.privateKey,
                format: 'pem',
                type: 'pkcs1',
                passphrase: SenderKeys.passphrase
            });
            const answer = JWS.verify(senderA_SignedMessage, SenderKeys.publicKey);
            expect(answer).toBeTruthy();
            const hydratedMessage = JSON.parse( JWS.decode( senderA_SignedMessage ) );
            expect( hydratedMessage ).toEqual( originalMessage );
        });
        test('should detect tampering', () => {
            const senderA_SignedMessage = JWS.encode(JSON.stringify(originalMessage), {
                key: SenderKeys.privateKey,
                format: 'pem',
                type: 'pkcs1',
                passphrase: SenderKeys.passphrase
            });
            const [joseStr, message, sig] = senderA_SignedMessage.split('.');
            const tamperedMessage = [joseStr,`${message}eyJfaWQiOiI1ZTE`,sig].join('.');
            const answer = JWS.verify(tamperedMessage, SenderKeys.publicKey);
            expect(answer).toBeFalsy();
        });
    });
    test('should encrypt and sign correctly',()=> {
        let Sender = BuildAKey();
        let Receiver = BuildAKey();
        // ------------------------------
        // Sender wants to give the { winingLotteryTicket: '21-17-24-22-13-31-27-14 24-6' } to Receiver
        //   - Receiver gives Sender their Public Key.
        //   - Sender gives Receiver their Public Key.
        // ------------------------------
        // from the Sender
        const originalMessage = { winingLotteryTicket: '21-17-24-22-13-31-27-14 24-6' };
        let SigningKey = {
            key: Sender.privateKey,
            format: 'pem',
            type: 'pkcs1',
            passphrase: Sender.passphrase
        };
        const encryptedMessage = JWS.encode(
            JWE.encrypt( JSON.stringify( originalMessage ), Receiver.publicKey, { cty: 'json' }),
            SigningKey
        );
        // ------------------------------
        // Receiver gets a big Base64 Encoded string.
        //   - Is it from who I think it is ?
        //   - What is the wining Lottery Ticket.
        // ------------------------------
        expect(
            JWS.verify( encryptedMessage, Sender.publicKey )
        ).toEqual( true );
        const transferredMessage = JSON.parse(
            JWE.decrypt(
                JWS.decode( encryptedMessage ),
                Receiver.privateKey,
                Receiver.passphrase
            )
        );
        expect(
            transferredMessage.winingLotteryTicket
        ).toEqual( '21-17-24-22-13-31-27-14 24-6' );
    })
})
