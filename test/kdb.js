/*
 * Licensed Materials - Property of IBM
 * (C) Copyright IBM Corp. 2017. All Rights Reserved.
 * US Government Users Restricted Rights - Use, duplication or disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
*/

const zcrypto = require("../");
const async = require('async');
const fs = require('fs');
const expect = require('chai').expect;
const should = require('chai').should;
const assert = require('chai').assert;
const tmp = require('tmp');


describe("zcrypto validation", function() {
  it("check kdb", function(done) {
    var crypt = new zcrypto.ZCrypto();
  
    var kdb_name = tmp.tmpNameSync({ dir: ".", prefix: 'a' });

    // Create a KDB file with a password, length and expiry time
    var rc = crypt.createKDB(kdb_name, "password", 10024, 0)
    expect(rc == 0).to.be.true;

    // Open kdb file if it exists
    crypt.openKDB(kdb_name, "password");

    // Import a P12 file as Cert.p12 using password and label
    // Update only allowed for KDB
    rc = crypt.importKey("Cert.p12", "password", "MYCERT3");
    expect(rc == 0).to.be.true;

    // Export to P12 using password and label
    var p12_name = tmp.tmpNameSync({ dir: ".", prefix: 'p' });
    var rc = crypt.exportKeyToFile(p12_name, "root", "MYCERT3");
    expect(rc == 0).to.be.true;

    expect(fs.existsSync(kdb_name)).to.be.true;
    expect(fs.existsSync(p12_name)).to.be.true;

    // Convert from KDB/RACF Keyring to a PEM file
    var pem = zcrypto.exportLabelToPEM(crypt, "MYCERT3", "root");
    expect(pem.key != undefined).to.be.true;

    if (fs.existsSync(kdb_name)) {
        fs.unlinkSync(kdb_name);
    }

    if (fs.existsSync(p12_name)) {
        fs.unlinkSync(p12_name);
    }
    
    done();
    });

  it("check keyring", function(done) {
    var crypt = new zcrypto.ZCrypto();
    // Racf Keyring
    var rc = crypt.openKeyRing("MYRING");
    expect(rc == 0).to.be.true;

    var pem = zcrypto.exportLabelToPEM(crypt, "ServerCert");
    expect(pem.key != undefined).to.be.true;
    
    done();
    });

});
