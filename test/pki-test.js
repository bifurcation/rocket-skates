// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert = require('chai').assert;
const forge  = require('node-forge');
const jose   = require('node-jose');
const pki    = require('../lib/pki');

let keys = forge.pki.rsa.generateKeyPair(1024);

function generateCSR(options) {
  let csr = forge.pki.createCertificationRequest();

  csr.publicKey = keys.publicKey;

  if (options.subject) {
    csr.setSubject(options.subject);
  }

  if (options.attributes) {
    csr.setAttributes(options.attributes);
  }

  csr.sign(keys.privateKey);

  let asn1 = forge.pki.certificationRequestToAsn1(csr);
  let der = forge.asn1.toDer(asn1);
  let bytes = new Buffer(forge.util.bytesToHex(der), 'hex');
  let base64url = jose.util.base64url.encode(bytes);

  return base64url;
}

let csrs = {
  valid: {
    subject:    [{shortName: 'CN', value: 'www2.example.com'}],
    attributes: [{
      name:       'extensionRequest',
      extensions: [{
        name:     'subjectAltName',
        altNames: [
          {type: 2, value: 'example.com'},
          {type: 2, value: 'www.example.com'}
        ]
      }]
    }]
  },

  nonCN: {
    subject: [{shortName: 'C', value: 'US'}]
  },

  multipleCN: {
    subject: [
      {shortName: 'CN', value: 'www.example.com'},
      {shortName: 'CN', value: 'www2.example.com'}
    ]
  },

  nonDNSCN: {
    subject: [{shortName: 'CN', value: '~~~not!a!dns!name~~~'}]
  },

  unknownAttr: {
    subject:    [{shortName: 'CN', value: 'www2.example.com'}],
    attributes: [{name: 'challengePassword', value: 'password'}]
  },

  multipleExtReq: {
    subject:    [{shortName: 'CN', value: 'www2.example.com'}],
    attributes: [
      {name: 'extensionRequest', extensions: []},
      {name: 'extensionRequest', extensions: []}
    ]
  },

  noExtReq: {
    subject:    [{shortName: 'CN', value: 'www2.example.com'}],
    attributes: []
  },

  unknownExt: {
    subject:    [{shortName: 'CN', value: 'www2.example.com'}],
    attributes: [{
      name:       'extensionRequest',
      extensions: [{name: 'basicConstraints', cA: true}]
    }]
  },

  multipleSAN: {
    subject:    [{shortName: 'CN', value: 'www2.example.com'}],
    attributes: [{
      name:       'extensionRequest',
      extensions: [
        {name: 'subjectAltName', altNames: [{type: 2, value: 'foo.com'}]},
        {name: 'subjectAltName', altNames: [{type: 2, value: 'foo.com'}]}
      ]
    }]
  },

  noSAN: {
    subject:    [{shortName: 'CN', value: 'www2.example.com'}],
    attributes: [{name: 'extensionRequest', extensions: []}]
  },

  nonDNS: {
    subject:    [{shortName: 'CN', value: 'www2.example.com'}],
    attributes: [{
      name:       'extensionRequest',
      extensions: [{
        name:     'subjectAltName',
        altNames: [{type: 6, value: 'https://foo.com'}]
      }]
    }]
  },

  nonDNSName: {
    subject:    [{shortName: 'CN', value: 'www2.example.com'}],
    attributes: [{
      name:       'extensionRequest',
      extensions: [{
        name:     'subjectAltName',
        altNames: [{type: 2, value: '~~~not!a!dns!name~~~'}]
      }]
    }]
  },

  noNames: {
    attributes: [{
      name: 'extensionRequest',
      extensions: [
      {name: 'subjectAltName', altNames: []}
      ]
    }]
  },

  noCN: {
    attributes: [{
      name:       'extensionRequest',
      extensions: [{
        name:     'subjectAltName',
        altNames: [{type: 2, value: '~~~not!a!dns!name~~~'}]
      }]
    }]
  }
};

function errorOn(test) {
  return () => {
    let csr = generateCSR(csrs[test]);
    let parsed = pki.parseCSR(csr);
    let result = pki.checkCSR(parsed);
    assert.isObject(result);
    assert.property(result, 'error');
  };
}

describe('PKI utilities module', () => {
  it('generates a random serial number', () => {
    let serial = pki.randomSerialNumber();
    assert.isString(serial);
    assert.ok(serial.match(/^[a-fA-F0-9]{32}$/));
  });

  it('parses a valid CSR', () => {
    let csr = generateCSR(csrs.valid);
    let parsed = pki.parseCSR(csr);
    assert.isObject(parsed);
  });

  it('accepts a valid CSR', () => {
    let csr = generateCSR(csrs.valid);
    let parsed = pki.parseCSR(csr);
    let result = pki.checkCSR(parsed);
    assert.isObject(result);
    assert.notProperty(result, 'error');
    assert.property(result, 'names');
    assert.deepEqual(result.names, ['www2.example.com', 'example.com', 'www.example.com']);
  });

  it('rejects a CSR with DN components other than CN',          errorOn('nonCN'));
  it('rejects a CSR with multiple CNs',                         errorOn('multipleCN'));
  it('rejects a CSR with a non-DNS CN',                         errorOn('nonDNSCN'));
  it('rejects a CSR with an unknown attribute',                 errorOn('unknownAttr'));
  it('rejects a CSR with multiple extensionRequest attributes', errorOn('multipleExtReq'));
  it('rejects a CSR with no extensionRequest attribute',        errorOn('noExtReq'));
  it('rejects a CSR with an unknown extension',                 errorOn('unknownExt'));
  it('rejects a CSR with multiple SAN extensions',              errorOn('multipleSAN'));
  it('rejects a CSR with no SAN extension',                     errorOn('noSAN'));
  it('rejects a CSR with a non-dNSName SAN',                    errorOn('nonDNS'));
  it('rejects a CSR with a dNSName SAN that is not a DNS name', errorOn('nonDNSName'));
  it('rejects a CSR with no names at all',                      errorOn('noNames'));
  it('rejects a CSR with DN components other than CN',          errorOn('noCN'));
});
