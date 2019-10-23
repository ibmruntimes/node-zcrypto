# zcrypto
This NodeJS module provides APIs to RACF keyrings and KDB (key databases)

## Installation

<!--
This is a [Node.js](https://nodejs.org/en/) module available through the
[npm registry](https://www.npmjs.com/).
-->

Node.js 8.16.0 for z/OS or higher is required.

## Simple to use

### Install

```bash
npm install zcrypto
```

### Use

```js
const zcrypto = require('./');

// Create an object of a zcrypto
var crypt = new zcrypto.ZCrypto();

// Create a KDB file with a password, length and expiry time
crypt.createKDB("my.kdb", "password", 10024, 0);

// Open kdb file if it exists
crypt.openKDB("my.kdb", "password");

// RACF Keyring
//crypt.openKeyRing("ITODORO");

// Import a P12 file as Cert.p12 using password and label
// Update only allowed for KDB
crypt.importKey("Cert.p12", "root", "MYCERT3");

// Export to P12 using password and label
crypt.exportKeyToFile("Cert.p12.nodedup", "root", "MYCERT3");

// Convert from KDB/RACF Keyring to a PEM file
var pem = zcrypto.ConvertP12LabelToPEM(crypt, "MYCERT3", "root");
console.log(pem.key);
console.log(pem.cert);

// Convert from P12 File to PEM
pem = zcrypto.ConvertP12FileToPEM("Cert.p12.nodedup", "root");
console.log(pem.key);
console.log(pem.cert);

// Launch a HTTPS web server
const https = require('https'); 

// Configuration for the HTTPS web server.
const options = {
  key: pem.key,
  cert: pem.cert,
};

// Create the https server and begin listening for requests.
https.createServer(options, (req, res) => {
  res.writeHead(200); 
  res.end('hello world\n'); 
}).listen(3000); // Listen for requests on port 3000.
```

### How to generate a pkcs12 for import into KDB
// Must be performed on a non-z/OS machine
openssl genrsa -out privatekey.pem 1024 openssl req -new -key privatekey.pem -out certrequest.csr
openssl x509 -req -in certrequest.csr -signkey privatekey.pem -out certificate.pem
openssl pkcs12 -export -out Cert.p12 -in certificate.pem -inkey privatekey.pem -passin pass:root -passout pass:root

### Troubleshooting

