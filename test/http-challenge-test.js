'use strict';

const assert          = require('chai').assert;
const nock            = require('nock');
const HTTP01Challenge = require('../lib/challenges/http-challenge.js');

const thumbprint = 'p3wl28h-9g3g1r6eIGORS5usGW79TUjL6fo_T5xRhAQ';

describe('http-01 challenge', function() {
  afterEach(() => {
    nock.cleanAll();
  });

  it('updates and does a query', function(done) {
    let challenge = new HTTP01Challenge('example.com', thumbprint);
    assert.equal(challenge.status, 'pending');

    let server = nock('http://example.com')
      .get('/.well-known/acme-challenge/' + challenge.token)
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

  it('rejects a response with the wrong type', function(done) {
    let challenge = new HTTP01Challenge('example.com', thumbprint);
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

  it('rejects a response with the wrong keyAuthorization', function(done) {
    let challenge = new HTTP01Challenge('example.com', thumbprint);
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

  it('rejects a bad validation response', function(done) {
    let challenge = new HTTP01Challenge('example.com', thumbprint);
    assert.equal(challenge.status, 'pending');

    let server = nock('http://example.com')
      .get('/.well-known/acme-challenge/' + challenge.token)
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

  it('invalidates on a server error', function(done) {
    let challenge = new HTTP01Challenge('example.com', thumbprint);
    assert.equal(challenge.status, 'pending');

    let server = nock('http://example.com')
      .get('/.well-known/acme-challenge/' + challenge.token)
      .reply(400);

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

  it('serializes properly', function(done) {
    let challenge = new HTTP01Challenge('example.com', thumbprint);
    let serialized = challenge.toJSON();

    console.log(serialized);

    assert.property(serialized, 'type');
    assert.property(serialized, 'status');
    assert.property(serialized, 'token');
    assert.notProperty(serialized, 'keyAuthorization');

    nock('http://example.com')
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
