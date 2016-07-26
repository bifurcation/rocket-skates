// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

//const assert             = require('chai').assert;
//const dns                = require('native-dns');
//const Promise            = require('bluebird');
//const crypto             = require('crypto');
//const jose               = require('../lib/jose');
//const TLSSNI02Validation = require('../lib/validations/tls-sni-validation');

describe('tls-sni-01 validation', () => {
  /*
  it('creates a correct response', (done) => {
    let challenge = {
      url:   'http://localhost:8081/chall/asdf',
      token: '12345'
    };
    let key;
    let keyAuthorization;

    jose.newkey()
      .then(k => {
        key = k;
        return key.thumbprint();
      })
      .then(tpBuf => {
        keyAuthorization = challenge.token + '.' + jose.base64url.encode(tpBuf);
        return TLSSNI02Validation.makeResponse(key, challenge);
      })
      .then(response => {
        assert.propertyVal(response, 'keyAuthorization', keyAuthorization);
        done();
      })
      .catch(done);
  });

  it('fulfills an dns-01 challenge', (done) => {
    let challenge = {
      url:   'http://localhost:8081/chall/asdf',
      token: '12345'
    };
    let response = {
      keyAuthorization: '12345.asdf'
    };
    let keyAuthorizationHashBuf = crypto.createHash('sha256')
                                        .update(response.keyAuthorization, 'utf8')
                                        .digest();
    let keyAuthorizationHash = jose.base64url.encode(keyAuthorizationHashBuf);

    let p = new Promise(resolve => {
      TLSSNI02Validation.respond('example.com', challenge, response, () => { resolve(); });
    });

    let authName = '_acme-challenge.example.com';
    let req = dns.Request({
      question: dns.Question({name: authName, type: 'TXT'}),
      server:   {
        address: TLSSNI02Validation.resolver,
        port:    TLSSNI02Validation.port
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
        done();
      })
      .catch(done);
  });
  */
});
