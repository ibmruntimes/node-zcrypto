const zcrypto = require('./');
const fs = require('fs')

function readKeysFromRACFKeyring() {
    var crypt = new zcrypto.ZCrypto();
    // Racf Keyring
    var rc = crypt.openKeyRing("TMYRING1");
    if (rc) {
        console.log(crypt.getErrorString(rc));
        return;
    }

    var pem = zcrypto.exportKeysToPKCS8(crypt, "TServerCert1");
    return pem;
}


var pem = readKeysFromRACFKeyring();
console.log(pem.key);
console.log(pem.cert);

// Load modules that we'll use.
const https = require('https'); // HTTPS web server.

// Configuration for the HTTPS web server.
const options = {
  key: pem.key,
  cert: pem.cert,
};

// Create the https server and begin listening for requests.
console.log("Listing on port 3000...\n");
https.createServer(options, (req, res) => {
  // This callback function will be called when someone makes a request to the https server.
  // req will contain the request data, while res will allow a response to be sent back.
  res.writeHead(200); // Set the HTTP response status codes to 200 OK.
  res.end('hello world\n'); // Write the string 'hello world\n' to the body, and send the response back.
}).listen(3000); // Listen for requests on port 3000.
