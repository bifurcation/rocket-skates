// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert           = require('chai').assert;
const rp               = require('request-promise');
const Promise          = require('bluebird');
const jose             = require('../lib/jose');
const HTTP01Validation = require('../lib/validations/http-validation.js');

HTTP01Validation.port = 8080;

describe('http-01 validation', () => {
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
        return HTTP01Validation.makeResponse(key, challenge);
      })
      .then(response => {
        assert.propertyVal(response, 'keyAuthorization', keyAuthorization);
        done();
      })
      .catch(done);
  });


  it('fulfills an http-01 challenge', (done) => {
    let challenge = {
      url:   'http://localhost:8081/chall/asdf',
      token: '12345'
    };
    let response = {
      keyAuthorization: '12345.asdf'
    };

    let p = new Promise(resolve => {
      HTTP01Validation.respond('localhost', challenge, response, () => { resolve(); });
    });

    p.then(() => Promise.delay(100))
      .then(() => {
        let url = `http://localhost:${HTTP01Validation.port}/`
                + `.well-known/acme-challenge/${challenge.token}`;
        return rp.get(url);
      })
      .then(text => {
        assert.equal(text, response.keyAuthorization);
        done();
      })
      .catch(done);
  });
});
