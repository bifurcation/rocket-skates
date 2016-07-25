// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert          = require('chai').assert;
const nock            = require('nock');
const HTTP01Challenge = require('../lib/challenges/http-challenge.js');

const thumbprint = 'p3wl28h-9g3g1r6eIGORS5usGW79TUjL6fo_T5xRhAQ';
const name = 'example.com';

describe('http-01 challenge', () => {
  afterEach(() => {
    nock.cleanAll();
  });

  it('updates and does a query', (done) => {
    let challenge = new HTTP01Challenge(name, thumbprint);
    assert.equal(challenge.status, 'pending');

    let server = nock(`http://${name}:${HTTP01Challenge.port}`)
      .get(`/.well-known/acme-challenge/${challenge.token}`)
      .reply(200, challenge._keyAuthorization);

    let response = {
      type:             HTTP01Challenge.type,
      keyAuthorization: challenge._keyAuthorization
    };
    challenge.update(response)
      .then(() => {
        assert.isTrue(server.isDone());
        assert.equal(challenge.status, 'valid');
        done();
      })
      .catch(done);
  });

  it('rejects a response with the wrong type', (done) => {
    let challenge = new HTTP01Challenge(name, thumbprint);
    let response = {
      type:             'not-http',
      keyAuthorization: challenge._keyAuthorization
    };

    challenge.update(response)
      .then(() => {
        assert.equal(challenge.status, 'invalid');
        done();
      })
      .catch(done);
  });

  it('rejects a response with the wrong keyAuthorization', (done) => {
    let challenge = new HTTP01Challenge(name, thumbprint);
    let response = {
      type:             HTTP01Challenge.type,
      keyAuthorization: challenge._keyAuthorization + '-not'
    };

    challenge.update(response)
      .then(() => {
        assert.equal(challenge.status, 'invalid');
        done();
      })
      .catch(done);
  });

  it('rejects a bad validation response', (done) => {
    let challenge = new HTTP01Challenge(name, thumbprint);
    assert.equal(challenge.status, 'pending');

    let server = nock(`http://${name}:${HTTP01Challenge.port}`)
      .get(`/.well-known/acme-challenge/${challenge.token}`)
      .reply(200, 'not what you are looking for');

    let response = {
      type:             HTTP01Challenge.type,
      keyAuthorization: challenge._keyAuthorization
    };
    challenge.update(response)
      .then(() => {
        assert.isTrue(server.isDone());
        assert.equal(challenge.status, 'invalid');
        done();
      })
      .catch(done);
  });

  it('invalidates on a server error', (done) => {
    let challenge = new HTTP01Challenge(name, thumbprint);
    assert.equal(challenge.status, 'pending');

    let server = nock(`http://${name}:${HTTP01Challenge.port}`)
      .get(`/.well-known/acme-challenge/${challenge.token}`)
      .reply(404);

    let response = {
      type:             HTTP01Challenge.type,
      keyAuthorization: challenge._keyAuthorization
    };
    challenge.update(response)
      .then(() => {
        assert.isTrue(server.isDone());
        assert.equal(challenge.status, 'invalid');
        done();
      })
      .catch(done);
  });

  it('serializes properly', (done) => {
    let challenge = new HTTP01Challenge(name, thumbprint);
    let serialized = challenge.toJSON();

    assert.property(serialized, 'type');
    assert.property(serialized, 'status');
    assert.property(serialized, 'token');
    assert.notProperty(serialized, 'keyAuthorization');

    nock(`http://${name}:${HTTP01Challenge.port}`)
      .get('/.well-known/acme-challenge/' + challenge.token)
      .reply(200, challenge._keyAuthorization);
    let response = {
      type:             HTTP01Challenge.type,
      keyAuthorization: challenge._keyAuthorization
    };
    challenge.update(response)
      .then(() => {
        let serialized2 = challenge.toJSON();

        assert.property(serialized2, 'type');
        assert.property(serialized2, 'status');
        assert.property(serialized2, 'token');
        assert.property(serialized2, 'keyAuthorization');

        assert.equal(serialized2.type, serialized.type);
        assert.equal(serialized2.token, serialized.token);

        done();
      })
      .catch(done);
  });
});
