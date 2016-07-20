// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert   = require('chai').assert;
const jose     = require('../lib/jose');
const nodeJose = require('node-jose');

describe('jose', () => {
  it('generate + sign + verify', (done) => {
    let header = {'nonce': 2, 'url': 'asdf'};
    let content = {'foo': 'bar'};

    jose.newkey()
      .then(k => {
        assert.ok(nodeJose.JWK.isKey(k));
        return k;
      })
      .then(k => jose.sign(k, content, header))
      .then(jws => {
        assert.ok(jws.protected);
        assert.ok(!jws.header);
        assert.ok(jws.payload);
        assert.ok(jws.signature);

        let payloadBytes = nodeJose.util.base64url.decode(jws.payload);
        let payloadJSON = nodeJose.util.utf8.encode(payloadBytes);
        let payload = JSON.parse(payloadJSON);
        assert.deepEqual(content, payload);
        return jws;
      })
      .then(jose.verify)
      .then(result => {
        assert.deepEqual(content, result.payload);
        done();
      })
      .catch(done);
  });

  it('rejects non-flattened JWS', (done) => {
    let jws = {
      'protected':  true,
      'payload':    'AAAA',
      'signatures': []
    };

    jose.verify(jws)
      .then(() => { assert.ok(false); })
      .catch(err => {
        assert.ok(err);
        done();
      });
  });

  it('refuses to sign JWS without required fields', (done) => {
    let header = {'foo': 'bar'};
    let content = {'foo': 'bar'};

    jose.newkey()
      .then(k => {
        assert.ok(nodeJose.JWK.isKey(k));
        return k;
      })
      .then(k => jose.sign(k, content, header))
      .then(() => { assert.ok(false); })
      .catch(err => {
        assert.ok(err);
        done();
      });
  });

  it('rejects verification of JWS without required fields', (done) => {
    let header = {
      'alg': 'ES256',
      'jwk': {}
    };
    let headerJSON = JSON.stringify(header);
    let headerBytes = nodeJose.util.utf8.decode(headerJSON);
    let headerB64 = nodeJose.util.base64url.encode(headerBytes);

    let jws = {
      'protected': headerB64,
      'payload':   'AAAA',
      'signature': 'AAAA'
    };

    jose.verify(jws)
      .then(() => { assert.ok(false); })
      .catch(err => {
        assert.ok(err);
        done();
      });
  });
});
