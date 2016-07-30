// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const jose  = require('node-jose');
const forge = require('node-forge');

let DNS_RE = /^([a-z0-9][a-z0-9-]{1,62}\.)+[a-z][a-z0-9-]{0,62}$/;

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


module.exports = {
  randomSerialNumber: randomSerialNumber,
  parseCSR:           parseCSR,
  checkCSR:           checkCSR
};
