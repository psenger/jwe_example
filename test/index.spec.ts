import {join} from 'path';
import {existsSync, readFileSync} from 'fs';
import JWE, {MEDIA_TYPES, ZIP} from '../src';

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
    {
        "_id": "5e13ff2fc36adf479e2de1bd",
        "index": 0,
        "guid": "f8d452ca-ecd7-498d-9b47-834891e6a9d6",
        "isActive": false,
        "balance": "$1,118.29",
        "picture": "http://placehold.it/32x32",
        "age": 31,
        "eyeColor": "blue",
        "name": {
            "first": "Grace",
            "last": "Cooley"
        },
        "company": "PRISMATIC",
        "email": "grace.cooley@prismatic.io",
        "phone": "+1 (819) 460-3587",
        "address": "614 Newport Street, Bellfountain, Massachusetts, 1459",
        "about": "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras faucibus orci gravida tortor semper, vitae faucibus nunc hendrerit. Curabitur molestie hendrerit sollicitudin. Aenean interdum erat nec nulla accumsan laoreet. Ut ornare id leo et luctus. Sed finibus lectus quis enim aliquet, maximus euismod tortor maximus. Donec tempus dapibus metus eu porttitor. Sed fermentum viverra vehicula. Cras interdum libero nec ligula tempor lacinia. Aliquam ut aliquet risus, sit amet tempus dui. In hac habitasse platea dictumst. Maecenas nec lorem porta, eleifend nunc at, posuere sem. Maecenas sit amet magna et quam sodales venenatis.",
        "registered": "Saturday, January 18, 2014 10:04 PM",
        "latitude": "-16.301792",
        "longitude": "31.544137",
        "tags": [
            "facebook",
            "myspace",
            "github",
            "linkedin"
        ],
        "range": [
            0,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9
        ],
        "friends": [
            {
                "id": 0,
                "name": "Mary Sosa"
            },
            {
                "id": 1,
                "name": "Jordan Prince"
            },
            {
                "id": 2,
                "name": "Day Bird"
            }
        ],
        "greeting": "Hello, Grace! You have 5 unread messages.",
        "favoriteFruit": "banana"
    }
);


let name: string;
let encryptedMessage: string;
let decryptedMessage: string;

describe('Encrypt with Decrypt', () => {
    const lo = (name:string, originalMessage: string , encryptedMessage : string, decryptedMessage:string) => console.log(`When the content is '${name}' \nOriginal Message length ${originalMessage.length}\nEncrypted Message length ${encryptedMessage.length}\nDecrypted Message length ${decryptedMessage.length}`);
    test('Should work when zipped is not passed',()=>{
        name = 'not zipped';
        encryptedMessage = jwe.encrypt(originalMessage, { cty: MEDIA_TYPES.JSON });
        decryptedMessage = jwe.decrypt(encryptedMessage);
        lo(name,originalMessage,encryptedMessage,decryptedMessage);
        expect(originalMessage).toEqual(decryptedMessage);
    })
    test('Should work when Zipped is passed',()=>{
        name = 'Zipped';
        encryptedMessage = jwe.encrypt(originalMessage, { zip: ZIP.GZIP, cty: MEDIA_TYPES.JSON });
        decryptedMessage = jwe.decrypt(encryptedMessage);
        lo(name,originalMessage,encryptedMessage,decryptedMessage);
        expect(originalMessage).toEqual(decryptedMessage);
    })
    test('should throw an error when the JOSE has been tampered with',()=>{
        const e = new Error('Unsupported state or unable to authenticate data');
        const t = () => {
            name = 'Tamper with JOSE';
            encryptedMessage = jwe.encrypt(originalMessage, { cty: MEDIA_TYPES.JSON });
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

            decryptedMessage = jwe.decrypt(encryptedMessage);
            lo(name,originalMessage,encryptedMessage,decryptedMessage);
        };
        expect(t).toThrow(e);
    })
});
