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
      return {error: 'Subject must have only commonName'};
    } else if (commonName) {
      return {error: 'Subject has multiple commonName values'};
    }

    commonName = attr.value.toLowerCase();
    if (!commonName.match(DNS_RE)) {
      return {error: 'Subject commonName is not a DNS name'};
    }
  }

  // Key has an acceptable algorithm / length
  // XXX: Forge doesn't really allow us to inspect this

  // No attributes besides extensionRequest
  let extensions;
  for (let attr of csr.attributes) {
    if (attr.name !== 'extensionRequest') {
      return {error: 'No attributes besides extensionRequest allowed'};
    } else if (extensions) {
      return {error: 'Multiple extensionRequest attributes'};
    }

    extensions = attr.extensions;
  }
  if (!extensions) {
    return {error: 'No extensions provided'};
  }

  // No extensions besides SAN
  let sans;
  for (let extn of extensions) {
    if (extn.name !== 'subjectAltName') {
      return {error: 'Forbidden extension type'};
    } else if (sans) {
      return {error: 'Multiple SAN extensions'};
    }

    sans = extn.altNames;
  }
  if (!sans) {
    return {error: 'No subjectAltName extension provided'};
  }

  // No SANs besides dNSName
  // CN and all dNSNames MUST be DNS names
  let names = {};
  if (commonName) {
    names[commonName] = true;
  }
  for (let san of sans) {
    if (san.type !== 2) {
      return {error: 'Non-dNSName SAN'};
    }

    let name = san.value.toLowerCase();
    if (!name.match(DNS_RE)) {
      return {error: 'dNSName SAN is not a DNS name'};
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
    return {error: 'No names in CSR'};
  }

  return {names: nameList};
}


module.exports = {
  randomSerialNumber: randomSerialNumber,
  parseCSR:           parseCSR,
  checkCSR:           checkCSR
};
