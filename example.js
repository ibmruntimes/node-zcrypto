const zcrypto = require('./');
const fs = require('fs')

if (fs.existsSync("my.kdb")) {
  fs.unlinkSync("my.kdb");
}
if (fs.existsSync("Cert.p12.nodedup")) {
  fs.unlinkSync("Cert.p12.nodedup");
}

var crypt = new zcrypto.ZCrypto();
crypt.createKDB("my.kdb", "password", 10024, 0);
crypt.importKey("Cert.p12", "root", "MYCERT3");
crypt.exportKeyToFile("Cert.p12.nodedup", "root", "MYCERT3");

var p12File = fs.readFileSync("Cert.p12.nodedup", "binary");
//console.log(p12File);
var pem = zcrypto.ConvertP12LabelToPEM(crypt, "MYCERT3", "root");
console.log(pem.key);
console.log(pem.cert);
pem = zcrypto.ConvertP12FileToPEM("Cert.p12.nodedup", "root");
console.log(pem.key);
console.log(pem.cert);

