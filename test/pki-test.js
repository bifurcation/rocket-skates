// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert = require('chai').assert;
const forge  = require('node-forge');
const jose   = require('node-jose');
const pki    = require('../lib/pki');

let csrKeys = forge.pki.rsa.generateKeyPair(1024);

function generateCSR(options) {
  let csr = forge.pki.createCertificationRequest();

  csr.publicKey = csrKeys.publicKey;

  if (options.subject) {
    csr.setSubject(options.subject);
  }

  if (options.attributes) {
    csr.setAttributes(options.attributes);
  }

  csr.sign(csrKeys.privateKey);

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
      name:       'extensionRequest',
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
    try {
      let csr = generateCSR(csrs[test]);
      let parsed = pki.parseCSR(csr);
      pki.checkCSR(parsed);
      assert.isTrue(false);
    } catch (e) {
      assert.isTrue(true);
    }
  };
}

let validCSR = generateCSR(csrs['valid']);
let notBefore = new Date('2017-01-01T00:00:00');
let notAfter = new Date('2017-02-01T00:00:00');
let apps = {
  'justCSR': {csr: validCSR},

  'withNotBefore': {
    csr:       validCSR,
    notBefore: notBefore
  },

  'withNotAfter': {
    csr:      validCSR,
    notAfter: notAfter
  },

  'withBoth': {
    csr:       validCSR,
    notBefore: notBefore,
    notAfter:  notAfter
  }
};

function testIssue(test) {
  return (done) => {
    let app = apps[test];
    localCA.issue(apps[test])
      .then(cert => {
        assert.instanceOf(cert, Buffer);

        let hex = cert.toString('hex');
        let der = forge.util.hexToBytes(hex);
        let asn1 = forge.asn1.fromDer(der);
        let parsed = forge.pki.certificateFromAsn1(asn1);

        if (app.notBefore) {
          assert.isTrue(app.notBefore - parsed.validity.notBefore === 0);
        }

        if (app.notAfter) {
          assert.isTrue(app.notAfter - parsed.validity.notAfter === 0);
        }

        done();
      })
      .catch(done);
  };
}

let localCA = new pki.CA();

describe('PKI utilities module', () => {
  it('parses a valid CSR', () => {
    let csr = generateCSR(csrs.valid);
    let parsed = pki.parseCSR(csr);
    assert.isObject(parsed);
  });

  it('accepts a valid CSR', () => {
    let csr = generateCSR(csrs.valid);
    let parsed = pki.parseCSR(csr);
    let result = pki.checkCSR(parsed);
    assert.isArray(result);
    assert.deepEqual(result, ['www2.example.com', 'example.com', 'www.example.com']);
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

  it('generates and caches keys', function(done) {
    this.timeout(10000);

    let firstKeys;
    localCA.keys()
      .then(keys => {
        assert.isObject(keys);
        assert.property(keys, 'privateKey');
        assert.property(keys, 'publicKey');

        firstKeys = keys;
        return localCA.keys();
      })
      .then(keys => {
        assert.deepEqual(keys, firstKeys);
        done();
      })
      .catch(done);
  });

  it('fails when key generation fails', (done) => {
    let gen = forge.rsa.generateKeyPair;
    forge.rsa.generateKeyPair = (opts, callback) => {
      callback(new Error('error'));
    };

    function cleanup(err) {
      forge.rsa.generateKeyPair = gen;
      done(err);
    }

    let ca = new pki.CA();
    ca.keys()
      .then(() => { cleanup(new Error('Generation should have failed')); })
      .catch(() => { cleanup(); });
  });

  it('issues a certificate with only a CSR', testIssue('justCSR'));
  it('issues a certificate with notBefore',  testIssue('withNotBefore'));
  it('issues a certificate with notAfter',   testIssue('withNotAfter'));
  it('issues a certificate with both',       testIssue('withBoth'));
});
