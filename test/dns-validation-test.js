// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert          = require('chai').assert;
const dns             = require('native-dns-multisocket');
const Promise         = require('bluebird');
const crypto          = require('crypto');
const cachedCrypto    = require('./tools/cached-crypto');
const jose            = require('../lib/jose');
const DNS01Validation = require('../lib/client/dns-validation.js');

DNS01Validation.resolver = '127.0.0.1';
DNS01Validation.port = 5300;

describe('dns-01 validation', () => {
  it('creates a correct response', (done) => {
    let challenge = {
      url:   'https://localhost:8081/chall/asdf',
      token: '12345'
    };
    let key;
    let keyAuthorization;

    cachedCrypto.key
      .then(k => {
        key = k;
        return key.thumbprint();
      })
      .then(tpBuf => {
        keyAuthorization = challenge.token + '.' + jose.base64url.encode(tpBuf);
        return DNS01Validation.makeResponse(key, challenge);
      })
      .then(response => {
        assert.propertyVal(response, 'keyAuthorization', keyAuthorization);
        done();
      })
      .catch(done);
  });

  it('fulfills an dns-01 challenge', (done) => {
    let challenge = {
      url:   'https://localhost:8081/chall/asdf',
      token: '12345'
    };
    let response = {
      keyAuthorization: '12345.asdf'
    };
    let keyAuthorizationHashBuf = crypto.createHash('sha256')
                                        .update(response.keyAuthorization, 'utf8')
                                        .digest();
    let keyAuthorizationHash = jose.base64url.encode(keyAuthorizationHashBuf);

    let validation;
    let p = new Promise(resolve => {
      validation = DNS01Validation.respond('example.com', challenge, response, resolve);
    });

    let authName = '_acme-challenge.example.com';
    let req = dns.Request({
      question: dns.Question({name: authName, type: 'TXT'}),
      server:   {
        address: DNS01Validation.resolver,
        port:    DNS01Validation.port,
        type:    'tcp'
      },
      timeout: 2000
    });

    p.then(() => Promise.delay(100))
      .then(() => {
        return new Promise((resolve, reject) => {
          req.on('timeout', () => { reject('timeout'); });
          req.on('message', (err, answer) => {
            if (err) {
              reject(err);
            }

            let results = answer.answer.map(a => {
              if (!a.data || !(a.data instanceof Array)) {
                return null;
              }
              return a.data.join('');
            })
              .filter(x => (x !== null));

            if (results.length === 0) {
              reject(new Error('No results'));
            }

            resolve(results[0]);
          });

          req.send();
        });
      })
      .timeout(1000)
      .then(text => {
        assert.equal(text, keyAuthorizationHash);
        return validation;
      })
      .then(() => { done(); })
      .catch(done);
  });

  it('rejects an invalid request', (done) => {
    let challenge = {
      url:   'https://localhost:8081/chall/asdf',
      token: '12345'
    };
    let response = {
      keyAuthorization: '12345.asdf'
    };

    let validation;
    let p = new Promise(resolve => {
      validation = DNS01Validation.respond('example.com', challenge, response, resolve);
    });

    let req = dns.Request({
      question: dns.Question({name: 'anonymous.invalid', type: 'TXT'}),
      server:   {
        address: DNS01Validation.resolver,
        port:    DNS01Validation.port,
        type:    'tcp'
      },
      timeout: 2000
    });

    p.then(() => Promise.delay(100))
      .then(() => {
        return new Promise((resolve, reject) => {
          req.on('timeout', () => { reject('timeout'); });
          req.on('message', (err, answer) => {
            if (err) {
              reject(err);
            }

            resolve(answer);
          });

          req.send();
        });
      })
      .timeout(1000)
      .then(answer => {
        assert.notEqual(answer.header.rcode, dns.consts.NAME_TO_RCODE.NOERROR);
        return validation;
      })
      .then(() => { done(); })
      .catch(done);
  });
});
