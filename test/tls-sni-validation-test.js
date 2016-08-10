// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert             = require('chai').assert;
const tls                = require('tls');
const Promise            = require('bluebird');
const crypto             = require('crypto');
const pem                = require('pem');
const cachedCrypto       = require('./tools/cached-crypto');
const jose               = require('../lib/jose');
const TLSSNI02Validation = require('../lib/client/tls-sni-validation');

TLSSNI02Validation.port = 4430;

describe('tls-sni-02 validation', () => {
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
        return TLSSNI02Validation.makeResponse(key, challenge);
      })
      .then(response => {
        assert.propertyVal(response, 'keyAuthorization', keyAuthorization);
        done();
      })
      .catch(done);
  });

  it('fulfills an  challenge', (done) => {
    let challenge = {
      url:   'https://localhost:8081/chall/asdf',
      token: '12345'
    };
    let response = {
      keyAuthorization: '12345.asdf'
    };

    let tokenHash = crypto.createHash('sha256')
                          .update(challenge.token, 'utf8')
                          .digest('hex').toLowerCase();
    let keyAuthorizationHash = crypto.createHash('sha256')
                                     .update(response.keyAuthorization, 'utf8')
                                     .digest('hex').toLowerCase();

    let sanA1 = tokenHash.substr(0, 32);
    let sanA2 = tokenHash.substr(32);
    let sanB1 = keyAuthorizationHash.substr(0, 32);
    let sanB2 = keyAuthorizationHash.substr(32);
    let sanA = `${sanA1}.${sanA2}.acme.invalid`;
    let sanB = `${sanB1}.${sanB2}.acme.invalid`;

    let options = {
      host:               'localhost',
      servername:         sanA,
      port:               TLSSNI02Validation.port,
      rejectUnauthorized: false
    };

    let p = new Promise(resolve => {
      TLSSNI02Validation.respond('example.com', challenge, response, resolve);
    });

    p.then(() => Promise.delay(100))
      .then(() => {
        return new Promise((resolve, reject) => {
          let stream = tls.connect(options, () => {
            let san = stream.getPeerCertificate().subjectaltname;
            stream.end();
            if (!san) {
              reject(new Error('No SAN in peer certificate'));
              return;
            }

            let foundSANA = (san.indexOf(`DNS:${sanA}`) > -1);
            let foundSANB = (san.indexOf(`DNS:${sanB}`) > -1);
            if (!foundSANA || !foundSANB) {
              reject(new Error('Required SANs not found'));
              return;
            }

            resolve();
          });
        });
      })
      .then(done)
      .catch(done);
  });

  it('fails if it is unable to create a certificate', (done) => {
    let challenge = {
      url:   'https://localhost:8081/chall/asdf',
      token: '12345'
    };
    let response = {
      keyAuthorization: '12345.asdf'
    };

    let create = pem.createCertificate;
    pem.createCertificate = (opts, callback) => {
      callback(new Error('error'));
    };

    function cleanup(err) {
      pem.createCertificate = create;
      done(err);
    }

    TLSSNI02Validation.respond('example.com', challenge, response)
      .then(() => { cleanup(new Error('tls-sni-02 challenge should have failed')); })
      .catch(() => { cleanup(); });
  });
});
