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

function ConvertP12LabelToPEM(obj, label, passphrase) {
	var p12File = obj.exportKeyToBuffer(passphrase, label);
	console.log(p12File);
	return ConvertP12ToPEM(ArrayToString(p12File), passphrase);
}

function ConvertP12FileToPEM(file, passphrase) {
    var p12File = fs.readFileSync(file, "binary");
	return ConvertP12ToPEM(p12File, passphrase);
}

zcrypto.ConvertP12LabelToPEM = ConvertP12LabelToPEM;
zcrypto.ConvertP12FileToPEM = ConvertP12FileToPEM;

module.exports = zcrypto;
