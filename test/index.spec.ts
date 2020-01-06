import {join} from 'path';
import {existsSync, readFileSync} from 'fs';
import JWE, {MEDIA_TYPES, OPTIONS, ZIP} from '../src';
import {randomBytes} from "crypto";
// import http from 'http';

const syncLoad = ( name: string ) => readFileSync(join(__dirname, name));
const ifMissing = ( name: string ) => ! existsSync(join(__dirname, name));
const privKey = 'privkey.pem';
const pubKey = 'pubkey.pem';
const password = process.env.PEM_PASSWORD;

if (password === undefined || password === null) {
    throw new Error('Missing password environment variable `PEM_PASSWORD`');
}

if (ifMissing(pubKey) || ifMissing(privKey)) {
    throw new Error('Missing required pem file');
}

const jwe = new JWE(password, syncLoad(pubKey), syncLoad(privKey));

const originalMessage = JSON.stringify(
    { message: 'hello' }
);


let name: string;
let encryptedMessage: string;
let decryptedMessage: string;

describe('Encrypt with Decrypt', () => {
    const lo = (name:string, originalMessage: string , encryptedMessage : string, decryptedMessage:string) => console.log(`When the content is '${name}' \nOriginal Message length ${originalMessage.length}\nEncrypted Message length ${encryptedMessage.length}\nDecrypted Message length ${decryptedMessage.length}`);
    test('Not zipped',()=>{
        name = 'not zipped';
        encryptedMessage = jwe.encrypt(originalMessage, { cty: MEDIA_TYPES.JSON });
        decryptedMessage = jwe.decrypt(encryptedMessage);
        lo(name,originalMessage,encryptedMessage,decryptedMessage);
        expect(originalMessage).toEqual(decryptedMessage);
    })
    test('Zipped',()=>{
        name = 'Zipped';
        encryptedMessage = jwe.encrypt(originalMessage, { zip: ZIP.GZIP, cty: MEDIA_TYPES.JSON });
        decryptedMessage = jwe.decrypt(encryptedMessage);
        lo(name,originalMessage,encryptedMessage,decryptedMessage);
        expect(originalMessage).toEqual(decryptedMessage);
    })
});
