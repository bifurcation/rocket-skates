// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const deepEqual = require('deep-equal');
const jose      = require('node-jose');
const forge     = require('node-forge');

const DNS_RE = /^([a-z0-9][a-z0-9-]{1,62}\.)+[a-z][a-z0-9-]{0,62}$/;
const DATE_TOLERANCE = 1000; // ignore milliseconds

function datesEqual(d1, d2) {
  return Math.abs(d1.getTime() - d2.getTime()) < DATE_TOLERANCE;
}

function randomSerialNumber() {
  return forge.util.bytesToHex(forge.random.getBytesSync(16));
}

function parseCSR(base64url) {
  let derBuf = jose.util.base64url.decode(base64url);
  let der = forge.util.hexToBytes(derBuf.toString('hex'));
  return forge.pki.certificationRequestFromAsn1(forge.asn1.fromDer(der));
}

function checkCSR(csr) {
  // No elements to Subject besides CN
  let commonName;
  for (let attr of csr.subject.attributes) {
    if (attr.name !== 'commonName') {
      throw new Error('Subject must have only commonName');
    } else if (commonName) {
      throw new Error('Subject has multiple commonName values');
    }

    commonName = attr.value.toLowerCase();
    if (!commonName.match(DNS_RE)) {
      throw new Error('Subject commonName is not a DNS name');
    }
  }

  // Key has an acceptable algorithm / length
  // XXX: Forge doesn't really allow us to inspect this

  // No attributes besides extensionRequest
  let extensions;
  for (let attr of csr.attributes) {
    if (attr.name !== 'extensionRequest') {
      throw new Error('No attributes besides extensionRequest allowed');
    } else if (extensions) {
      throw new Error('Multiple extensionRequest attributes');
    }

    extensions = attr.extensions;
  }
  if (!extensions) {
    throw new Error('No extensions provided');
  }

  // No extensions besides SAN
  let sans;
  for (let extn of extensions) {
    if (extn.name !== 'subjectAltName') {
      throw new Error('Forbidden extension type');
    } else if (sans) {
      throw new Error('Multiple SAN extensions');
    }

    sans = extn.altNames;
  }
  if (!sans) {
    throw new Error('No subjectAltName extension provided');
  }

  // No SANs besides dNSName
  // CN and all dNSNames MUST be DNS names
  let names = {};
  if (commonName) {
    names[commonName] = true;
  }
  for (let san of sans) {
    if (san.type !== 2) {
      throw new Error('Non-dNSName SAN');
    }

    let name = san.value.toLowerCase();
    if (!name.match(DNS_RE)) {
      throw new Error('dNSName SAN is not a DNS name');
    }

    names[name] = true;
  }

  let nameList = [];
  for (let name in names) {
    if (names.hasOwnProperty(name)) {
      nameList.push(name);
    }
  }

  if (nameList.length === 0) {
    throw new Error('No names in CSR');
  }

  return nameList;
}

// Tests:
// * cert.notBefore == notBefore
// * cert.notAfter  == notAfter
// * cert.subject == csr.subject
// * cert.key == csr.key
// * cert.SAN == csr.SAN
function checkCertMatch(certDERBuf, csrB64url, notBefore, notAfter) {
  if (!csrB64url) {
    throw new Error('No CSR provided');
  }
  let csr = parseCSR(csrB64url);

  let certDER = forge.util.hexToBytes(certDERBuf.toString('hex'));
  let cert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(certDER));

  if (notBefore && !datesEqual(notBefore, cert.validity.notBefore)) {
    throw new Error('notBefore date does not match');
  }

  if (notAfter && !datesEqual(notAfter, cert.validity.notAfter)) {
    throw new Error('notAfter date does not match');
  }

  // forge provides convenient hashes for comparison
  if (csr.subject.hash !== cert.subject.hash) {
    throw new Error('Subject does not match');
  }

  // XXX: This is kind of gross, but the only real way that we can compare
  // keys produced by node-forge
  if (!deepEqual(csr.publicKey.n, cert.publicKey.n) ||
      !deepEqual(csr.publicKey.e, cert.publicKey.e)) {
    throw new Error('Public key does not match');
  }

  let csrSAN = csr.attributes.filter(attr => attr.name === 'extensionRequest')
                             .map(attr => attr.extensions
                                .filter(extn => extn.name === 'subjectAltName')
                                .map(extn => extn.altNames
                                  .map(san => san.value)
                                  .sort()));
  let certSAN = cert.extensions.filter(extn => extn.name === 'subjectAltName')
                               .map(extn => extn.altNames
                                 .map(san => san.value)
                                 .sort());
  if (csrSAN.length > 0 && !deepEqual(csrSAN[0], certSAN)) {
    throw new Error('subjectAltName extension does not match');
  }
}

function certNames(certDERBuf) {
  let certDER = forge.util.hexToBytes(certDERBuf.toString('hex'));
  let cert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(certDER));

  let names = [];

  let cn = cert.subject.getField('CN');
  if (cn) {
    names.push(cn.value);
  }

  let san = cert.getExtension('subjectAltName');
  if (san) {
    names = names.concat(san.altNames.filter(name => name.type === 2)
                                     .map(name => name.value));
  }

  let known = {};
  let uniqueNames = [];
  for (let name of names) {
    if (!known[name]) {
      uniqueNames.push(name);
    }
    known[name] = true;
  }

  return uniqueNames;
}

function certKeyThumbprint(certDERBuf) {
  return jose.JWK.asKey(certDERBuf, 'x509')
    .then(jwk => jwk.thumbprint())
    .then(tp => jose.util.base64url.encode(tp));
}

class CA {
  generate() {
    let options = {
      bits:    CA.publicKeyBits,
      e:       0x10001,
      workers: -1
    };

    return new Promise((resolve, reject) => {
      forge.pki.rsa.generateKeyPair(options, (err, keys) => {
        if (err) {
          reject(err);
        } else {
          this._keys = keys;
          resolve(keys);
        }
      });
    });
  }

  keys() {
    if (this._keys) {
      return Promise.resolve(this._keys);
    }

    return this.generate();
  }

  issue(app) {
    let notBefore;
    let notAfter;

    if (app.notBefore) {
      notBefore = new Date(app.notBefore);
    } else {
      notBefore = new Date();
    }

    if (app.notAfter) {
      notAfter = new Date(app.notAfter);
    } else {
      notAfter = new Date();
      notAfter.setTime(notBefore.getTime() + 1000 * CA.defaultValiditySeconds);
    }

    let csr = parseCSR(app.csr);
    let names = checkCSR(csr);
    let altNames = names.map(name => {
      return {type: 2, value: name};
    });

    return this.keys()
      .then(keys => {
        let cert = forge.pki.createCertificate();

        cert.serialNumber = randomSerialNumber();
        cert.validity.notBefore = notBefore;
        cert.validity.notAfter = notAfter;
        cert.subject = csr.subject;
        cert.publicKey = csr.publicKey;

        cert.setIssuer(CA.distinguishedName);
        cert.setExtensions([
          { name: 'basicConstraints', cA: false },
          { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
          { name: 'extKeyUsage', serverAuth: true },
          { name: 'subjectAltName', altNames: altNames }
        ]);

        cert.sign(keys.privateKey);
        let der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert));
        let buf = new Buffer(forge.util.bytesToHex(der), 'hex');
        return buf;
      });
  }
}

CA.defaultValiditySeconds = 90 * 24 * 3600;
CA.maxValiditySeconds = 365 * 24 * 3600;
CA.publicKeyBits = 2048;
CA.distinguishedName = [{ name: 'commonName', 'value': 'Happy Hacker Fake CA' }];

module.exports = {
  parseCSR:          parseCSR,
  checkCSR:          checkCSR,
  checkCertMatch:    checkCertMatch,
  certKeyThumbprint: certKeyThumbprint,
  certNames:         certNames,
  CA:                CA
};
