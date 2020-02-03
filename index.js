var forge = require("node-forge");
const fs = require('fs')
const zcrypto = require('./build/Release/zcrypto.node');

function ArrayToString(array) {
    var out, i, len, c;
    out = "";
    len = array.length;
    i = 0;
    while(i < len) {
      c = array[i++];
      out += String.fromCharCode(c);
    }

    return out;
}

function ConvertP12ToPEM(string, passphrase) {
	var asn = forge.asn1.fromDer(string, false)
	var p12 = forge.pkcs12.pkcs12FromAsn1(asn, false, passphrase);
	var bags = p12.getBags({bagType: forge.pki.oids.certBag});

	var bag = bags[forge.pki.oids.certBag][0];

	var keyData = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag]
			.concat(p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag]);
	var certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag];

	var certificate = forge.pki.certificateToPem(certBags[0].cert);

	var key = keyData.length ? forge.pki.privateKeyToPem(keyData[0].key) : undefined;

	return {
        key: key,
        cert: certificate,
    };
}

function exportLabelToPEM(obj, label, passphrase = "root") {
	var p12File = obj.exportKeyToBuffer(passphrase, label);
	return ConvertP12ToPEM(ArrayToString(p12File), passphrase);
}

function exportP12FileToPEM(file, passphrase = "root") {
    var p12File = fs.readFileSync(file, "binary");
	return ConvertP12ToPEM(p12File, passphrase);
}

zcrypto.exportLabelToPEM = exportLabelToPEM;
zcrypto.exportP12FileToPEM = exportP12FileToPEM;

module.exports = zcrypto;
