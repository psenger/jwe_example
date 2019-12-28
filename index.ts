import {join} from 'path';
import {existsSync, readFileSync} from 'fs';
import jwe from './utils';
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

const Jwe = new jwe(password, syncLoad(pubKey), syncLoad(privKey));

[
    ['not zipped', {} ],
    ['zipped', {zip: 'GZIP'}]
].map(([name,option]) => {
    const rb: Buffer = randomBytes( 1000000 );
    const originalMessage : string = rb.toString('hex');
    let encryptedMessage = Jwe.encrypt(originalMessage, option);
    let decryptedMessage = Jwe.decrypt(encryptedMessage);
    console.log(`When the content is '${name}' the decrypted message length is`, decryptedMessage.length);
    if (decryptedMessage === originalMessage) {
        console.log('Success');
    } else {
        console.error('Fail');
    }
});


