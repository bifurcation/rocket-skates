// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert         = require('chai').assert;
const dns            = require('native-dns-multisocket');
const DNS01Challenge = require('../lib/server/dns-challenge.js');

const thumbprint = 'p3wl28h-9g3g1r6eIGORS5usGW79TUjL6fo_T5xRhAQ';
const name = 'example.com';
const authName = '_acme-challenge.' + name;

const port = 5300;
DNS01Challenge.resolver = '127.0.0.1';
DNS01Challenge.port = port;

let record;
let gotRequest = false;
let server = dns.createServer();

server.on('request', (request, response) => {
  gotRequest = true;

  if (request.question.length === 0) {
    response.header.rcode = dns.consts.NAME_TO_RCODE.FORMERR;
  } else if ((request.question[0].class !== dns.consts.NAME_TO_QCLASS.IN) ||
      (request.question[0].type !== dns.consts.NAME_TO_QTYPE.TXT) ||
      (request.question[0].name !== authName)) {
    response.header.rcode = dns.consts.NAME_TO_RCODE.NOTFOUND;
  } else {
    response.answer.push(record);
  }

  response.send();
});


describe('dns-01 challenge', () => {
  before(() => {
    server.serve(port);
  });

  after((done) => {
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
    gotRequest = false;

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
    gotRequest = false;

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
    let originalResolver = DNS01Challenge.resolver;
    DNS01Challenge.resolver = 'auto';

    let challenge = new DNS01Challenge(name, thumbprint);
    assert.equal(challenge.status, 'pending');

    let response = {
      type:             DNS01Challenge.type,
      keyAuthorization: challenge._keyAuthorization
    };
    challenge.update(response)
      .then(() => {
        assert.isTrue(gotRequest);
        assert.equal(challenge.status, 'invalid');
        DNS01Challenge.resolver = originalResolver;
        done();
      })
      .catch(err => {
        DNS01Challenge.resolver = originalResolver;
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
