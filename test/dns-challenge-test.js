// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert         = require('chai').assert;
const Promise        = require('bluebird');
const dns            = require('native-dns-multisocket');
const DNS01Challenge = require('../lib/server/dns-challenge.js');

const thumbprint = 'p3wl28h-9g3g1r6eIGORS5usGW79TUjL6fo_T5xRhAQ';
const name = 'example.com';
const authName = '_acme-challenge.' + name;

const port = 5300;
DNS01Challenge.resolver = '127.0.0.1';
DNS01Challenge.port = port;

describe('dns-01 challenge', () => {
  let gotRequest;
  let server;
  let record;
  let delay = 10;

  beforeEach(() => {
    gotRequest = false;

    server = dns.createTCPServer();
    server.on('request', (request, response) => {
      gotRequest = true;

      Promise.delay(delay).then(() => {
        response.answer.push(record);
        response.send();
      })
        // If the client hangs up we can get an error; ignore it
        .catch(() => {});
    });
    server.serve(port);
  });

  afterEach((done) => {
    server.on('close', () => { done(); });
    server.close();
  });

  it('updates and does a query', done => {
    let challenge = new DNS01Challenge(name, thumbprint);
    assert.equal(challenge.status, 'pending');

    record = dns.TXT({
      name: authName,
      data: [challenge._keyAuthorizationHash],
      ttl:  600
    });

    let response = {
      type:             DNS01Challenge.type,
      keyAuthorization: challenge._keyAuthorization
    };
    challenge.update(response)
      .then(() => {
        assert.isTrue(gotRequest);
        assert.equal(challenge.status, 'valid');
        assert.property(challenge, 'validated');
        done();
      })
      .catch(done);
  });

  it('rejects a response with the wrong type', done => {
    let challenge = new DNS01Challenge(name, thumbprint);
    let response = {
      type:             'not-dns',
      keyAuthorization: challenge._keyAuthorization
    };

    challenge.update(response)
      .then(() => {
        assert.equal(challenge.status, 'invalid');
        done();
      })
      .catch(done);
  });

  it('rejects a response with the wrong keyAuthorization', done => {
    let challenge = new DNS01Challenge(name, thumbprint);
    let response = {
      type:             DNS01Challenge.type,
      keyAuthorization: challenge._keyAuthorization + '-not'
    };

    challenge.update(response)
      .then(() => {
        assert.equal(challenge.status, 'invalid');
        done();
      })
      .catch(done);
  });

  it('rejects a bad validation response', done => {
    let challenge = new DNS01Challenge(name, thumbprint);
    assert.equal(challenge.status, 'pending');

    record = dns.TXT({
      name: authName,
      data: [challenge._keyAuthorizationHash + '-not'],
      ttl:  600
    });

    let response = {
      type:             DNS01Challenge.type,
      keyAuthorization: challenge._keyAuthorization
    };
    challenge.update(response)
      .then(() => {
        assert.isTrue(gotRequest);
        assert.equal(challenge.status, 'invalid');
        done();
      })
      .catch(done);
  });

  it('invalidates on timeout', done => {
    let challenge = new DNS01Challenge(name, thumbprint);
    assert.equal(challenge.status, 'pending');

    let originalTimeout = 100;
    DNS01Challenge.timeout = 100;
    delay = 200;

    let response = {
      type:             DNS01Challenge.type,
      keyAuthorization: challenge._keyAuthorization
    };
    challenge.update(response)
      .then(() => {
        DNS01Challenge.timeout = originalTimeout;
        assert.isTrue(gotRequest);
        assert.equal(challenge.status, 'invalid');
        done();
      })
      .catch(err => {
        DNS01Challenge.timeout = originalTimeout;
        done(err);
      });
  });

  it('serializes properly', done => {
    let challenge = new DNS01Challenge(name, thumbprint);
    let serialized = challenge.toJSON();

    assert.property(serialized, 'type');
    assert.property(serialized, 'status');
    assert.property(serialized, 'token');
    assert.notProperty(serialized, 'keyAuthorization');

    record = dns.TXT({
      name: authName,
      data: [challenge._keyAuthorizationHash + '-not'],
      ttl:  600
    });
    gotRequest = false;

    let response = {
      type:             DNS01Challenge.type,
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
