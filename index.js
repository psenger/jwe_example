const path = require('path'),
    fs = require('fs');

const syncLoad = name => fs.readFileSync(path.join(__dirname, name));
const ifMissing = name => ! fs.existsSync(path.join(__dirname, name));
const privKey = 'privkey.pem';
const pubKey = 'pubkey.pem';
const password = process.env.PEM_PASSWORD;

if (password === undefined || password === null) {
    throw new Error('Missing password environment variable `PEM_PASSWORD`');
}

if (ifMissing(pubKey) || ifMissing(privKey)) {
    throw new Error('Missing required pem file');
}

const utils = require('./utils')(password, syncLoad(pubKey), syncLoad(privKey));

let enc = utils.encrypt('The true sign of intelligence is not knowledge but imagination.');
console.log('enc=', JSON.stringify(enc, null, 4));
let msg = utils.decrypt(enc);
console.log(msg);

