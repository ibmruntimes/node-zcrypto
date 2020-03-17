const zcrypto = require('./');
const fs = require('fs')

var crypt;

function readKeysFromRACFKeyring() {
    crypt = new zcrypto.ZCrypto();
    // Racf Keyring
    var rc = crypt.openKeyRing("TMYRING1");
    if (rc) {
        console.log(crypt.getErrorString(rc));
        return;
    }

    var pem = zcrypto.exportCertToPEM(crypt, "TCACert1");
    return pem;
}


var pem = readKeysFromRACFKeyring();

// Load modules that we'll use.
const https = require('https'); // HTTPS web server.

var options = { 
    hostname: 'hostname',
    port: 3000, 
    path: '/', 
    method: 'GET',
    ca: pem
}; 
var req = https.request(options, function(res) { 
    res.on('data', function(data) { 
        process.stdout.write(data); 
    }); 
}); 
req.end();
