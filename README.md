# zcrypto
This NodeJS module provides APIs to RACF keyrings and KDB (key databases) in z/OS.

## Background

This module leverages the Certificate Management Services (CMS) API.
These APIs can be used to create/manage your own key database files,
and extract certificates stored in the key database file or RACF key ring.

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

### Using zcrypto with RACF Keyrings
This assumes that a RACF Keyring was created and connected to a RACF private/public certificate and certificate authority.

```js
const zcrypto = require('zcrypto');

// Create an object of a zcrypto
var crypt = new zcrypto.ZCrypto();

// Open RACF Keyring labelled MYRING1
crypt.openKeyRing("MYRING1");

// Export RACF certificate labeled "ServerCert" to PEM format
var pem = zcrypto.exportLabelToPEM(crypt, "ServerCert");

// Launch a HTTPS web server with private key and certificate authority
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

### Using zcrypto with KDB (Key Databases)

```js
const zcrypto = require('zcrypto');

// Create an object of a zcrypto
var crypt = new zcrypto.ZCrypto();

// Example: Create a KDB file with a password, length and expiry time
crypt.createKDB("my.kdb", "root", 10024, 0);

// Example: Open kdb file if it exists
crypt.openKDB("my.kdb", "root");

// Import a P12 file as Cert.p12 using password and label
// Update only allowed for KDB
crypt.importKey("Cert.p12", "root", "MYCERT3");

// Export to P12 using password and label
var pem = crypt.exportKeyToFile("Cert.p12.nodedup", "root", "MYCERT3");

// Or export directly from a P12 File to PEM
pem = zcrypto.exportP12FileToPEM("Cert.p12", "root");

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

### Examples
See [examples](/examples) 

### How to generate a RACF private/public certificate and RACF keyring
Ensure that your z/OS Userid has CONTROL access to RACF facility classes IRR.DIGTCERT.GENCERT, IRR.DIGTCERT.CERTAUTH, and IRR.DIGTCERT.ADD

Modify and submit job cert.jcl:
`submit cert.jcl`

### How to generate a pkcs12 for import into KDB
```bash
// Must be performed on a non-z/OS machine and then transferred to z/OS as binary
openssl genrsa -out privatekey.pem 1024 openssl req -new -key privatekey.pem -out certrequest.csr
openssl x509 -req -in certrequest.csr -signkey privatekey.pem -out certificate.pem
openssl pkcs12 -export -out Cert.p12 -in certificate.pem -inkey privatekey.pem -passin pass:password -passout pass:password
```
