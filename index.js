const path = require('path'),
    fs = require('fs');

const syncLoad = name => fs.readFileSync(path.join(__dirname, name ));

const utils = require('./utils')( 'password', syncLoad('public.pem'), syncLoad('key.pem') );

let enc = utils.encrypt('The true sign of intelligence is not knowledge but imagination.' ) ;
console.log('enc=', JSON.stringify(enc, null, 4));
let msg = utils.decrypt( enc );
console.log(msg);

