// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const jose  = require('../../lib/jose');
const forge = require('node-forge');
const pem   = require('pem');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const certOptions = {
  commonName: 'example.com',
  selfSigned: true
};

let serverOptions;
let key;

let duration = 90 * 24 * 60 * 60 * 1000;
let notBefore = new Date();
let notAfter = new Date(notBefore.getTime() + duration);
let names = ['not-example.com', 'www.not-example.com'];

let keys = forge.pki.rsa.generateKeyPair(1024);
let issuer = [{ name: 'commonName', value: 'Happy Hacker Fake CA' }];
let subject = [{ name: 'commonName', value: names[0] }];
let altNames = names.map(name => { return { type: 2, value: name }; });
let serial = forge.util.bytesToHex(forge.random.getBytesSync(16));

// Generate a CSR with the above parameters
let csr = forge.pki.createCertificationRequest();
csr.publicKey = keys.publicKey;
csr.setSubject(subject);
csr.setAttributes([{
  name:       'extensionRequest',
  extensions: [{ name: 'subjectAltName', altNames: altNames }]
}]);

csr.sign(keys.privateKey);
let csrDER = forge.asn1.toDer(forge.pki.certificationRequestToAsn1(csr));
let csrBuf = new Buffer(forge.util.bytesToHex(csrDER), 'hex');
let csrB64url = jose.base64url.encode(csrBuf);

// Generate a certificate with the above parameters
let cert = forge.pki.createCertificate();
cert.publicKey = keys.publicKey;
cert.serialNumber = serial;
cert.validity.notBefore = notBefore;
cert.validity.notAfter = notAfter;
cert.setSubject(subject);
cert.setIssuer(issuer);
cert.setExtensions([
  { name: 'basicConstraints', cA: false },
  {
    name:             'keyUsage',
    digitalSignature: true,
    keyEncipherment:  true
  },
  { name: 'extKeyUsage', serverAuth: true },
  { name: 'subjectAltName', altNames: altNames },
  { name: 'subjectKeyIdentifier' }
]);

cert.sign(keys.privateKey);
let certDER = forge.asn1.toDer(forge.pki.certificateToAsn1(cert));
let certBuf = new Buffer(forge.util.bytesToHex(certDER), 'hex');

module.exports = {
  get tlsConfig() {
    if (serverOptions) {
      return Promise.resolve(serverOptions);
    }

    return new Promise((resolve, reject) => {
      pem.createCertificate(certOptions, (err, obj) => {
        if (err) {
          reject(err);
          return;
        }

        serverOptions = {
          key:  obj.serviceKey,
          cert: obj.certificate
        };
        resolve(serverOptions);
      });
    });
  },

  get key() {
    if (key) {
      return Promise.resolve(key);
    }

    return jose.newkey()
      .then(k => {
        key = k;
        return k;
      });
  },

  certReq: {
    csr:        csrB64url,
    notBefore:  notBefore,
    notAfter:   notAfter,
    names:      names,
    cert:       certBuf,
    privateKey: keys.privateKey,
    publicKey:  keys.publicKey
  }
};
