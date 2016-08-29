// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const chai            = require('chai');
const assert          = chai.assert;
const chaiAsPromised  = require('chai-as-promised');
const nock            = require('nock');
const cachedCrypto    = require('./tools/cached-crypto');
const jose            = require('../lib/jose');
const TransportClient = require('../lib/client/transport-client');

chai.use(chaiAsPromised);

describe('transport-level client', () => {
  afterEach(() => {
    nock.cleanAll();
  });

  it('fails if no account key is provided', () => {
    try {
      new TransportClient({});
      assert.ok(false);
    } catch (e) {
      assert.ok(true);
    }
  });

  it('rejects requests to non-HTTPS URLs', () => {
    assert.isRejected(TransportClient.get('http://example.com'));
    assert.isRejected(TransportClient.poll('http://example.com'));

    assert.isRejected(cachedCrypto.key.then(k => {
      let client = new TransportClient({accountKey: k});
      client.nonces.push('asdf');
      return client.post('http://example.com/foo', {'foo': 'bar'});
    }));
  });

  it('performs a JSON GET request', (done) => {
    let content = {'result': true};
    let headers = {
      'location': 'https://example.com/asdf',
      'link':     '<https://example.com/terms>; rel="terms-of-service"'
    };
    nock('https://example.com')
      .get('/foo').reply(200, content, headers);

    TransportClient.get('https://example.com/foo')
      .then(response => {
        assert.equal(response.location, headers.location);
        assert.property(response.links, 'terms-of-service');
        assert.deepEqual(response.links['terms-of-service'].url, 'https://example.com/terms');
        assert.deepEqual(response.body, content);
        done();
      })
      .catch(done);
  });

  it('performs a binary GET request', (done) => {
    let content = 'asdf';
    nock('https://example.com')
      .get('/foo').reply(200, content);

    TransportClient.get('https://example.com/foo', true)
      .then(response => {
        assert.isTrue(response.body instanceof Buffer);
        assert.equal(response.body.toString(), content);
        done();
      })
      .catch(done);
  });

  it('polls until completion', (done) => {
    let test = (res => res.body.foo);
    nock('https://example.com')
      .get('/foo').reply(200, {})
      .get('/foo').reply(200, {'foo': 'bar'});

    TransportClient.poll('https://example.com/foo', test)
      .then(body => {
        assert.ok(test(body));
        done();
      })
      .catch(done);
  });

  it('times out after a specified number of polls', (done) => {
    let test = (res => res.body.foo);
    nock('https://example.com')
      .get('/foo').reply(200, {})
      .get('/foo').reply(200, {})
      .get('/foo').reply(200, {})
      .get('/foo').reply(200, {'foo': 'bar'});

    TransportClient.poll('https://example.com/foo', test, 2, 10)
      .then(() => { done(new Error('should have failed')); })
      .catch(() => { done(); });
  });

  it('sends a POST with no preflight', (done) => {
    let gotHEAD = false;
    let gotPOST = false;
    let nonce = 'foo';
    let headers = {
      'location': 'https://example.com/asdf',
      'link':     '<https://example.com/terms>; rel="terms-of-service"'
    };
    nock('https://example.com')
      .head('/foo').reply((uri, requestBody, cb) => {
        gotHEAD = true;
        cb(null, [200, '', {'replay-nonce': nonce}]);
      })
      .post('/foo').reply((uri, jws, cb) => {
        gotPOST = true;
        jose.verify(jws)
          .then(result => {
            assert.equal(result.header.nonce, nonce);
            assert.ok(result.header.url);
            cb(null, [200, '', headers]);
          })
          .catch(err => {
            cb(null, [400, err.message]);
          });
      });

    cachedCrypto.key
      .then(k => {
        let client = new TransportClient({accountKey: k});
        client.nonces.push(nonce);
        return client.post('https://example.com/foo', {'foo': 'bar'});
      })
      .then(response => {
        assert.isFalse(gotHEAD);
        assert.isTrue(gotPOST);

        assert.equal(response.location, 'https://example.com/asdf');
        assert.property(response.links, 'terms-of-service');
        assert.deepEqual(response.links['terms-of-service'].url, 'https://example.com/terms');

        done();
      })
      .catch(done);
  });

  it('sends a POST with preflight', (done) => {
    let gotHEAD = false;
    let gotPOST = false;
    let nonce = 'foo';
    nock('https://example.com')
      .head('/foo').reply((uri, requestBody, cb) => {
        gotHEAD = true;
        cb(null, [200, '', {'replay-nonce': nonce}]);
      })
      .post('/foo').reply((uri, jws, cb) => {
        gotPOST = true;
        jose.verify(jws)
          .then(result => {
            assert.equal(result.header.nonce, nonce);
            assert.ok(result.header.url);
            cb(null, [200, '', {'replay-nonce': nonce}]);
          })
          .catch(err => {
            cb(null, [400, err.message]);
          });
      });

    cachedCrypto.key
      .then(k => {
        let client = new TransportClient({accountKey: k});
        return client.post('https://example.com/foo', {'foo': 'bar'});
      })
      .then(() => {
        assert.isTrue(gotHEAD);
        assert.isTrue(gotPOST);
        done();
      })
      .catch(done);
  });

  it('fails POST if preflight fails', (done) => {
    nock('https://example.com')
      .head('/foo').reply(200);

    cachedCrypto.key
      .then(k => {
        let client = new TransportClient({accountKey: k});
        return client.post('https://example.com/foo', {'foo': 'bar'});
      })
      .then(() => { done(new Error('should have failed')); })
      .catch(() => { done(); });
  });

  function testRetryAfter(retryAfter) {
    return (done) => {
      if (typeof(retryAfter) == 'function') {
        retryAfter = retryAfter();
      }

      let gotFirstPOST = false;
      let gotSecondPOST = false;
      let problemHeaders = {'retry-after': retryAfter};
      let problemResponse = {'type': 'urn:ietf:params:acme:error:rateLimited'};

      nock('https://example.com')
        .post('/foo').reply((uri, jws, cb) => {
          gotFirstPOST = true;
          cb(null, [403, problemResponse, problemHeaders]);
        })
        .post('/foo').reply((uri, jws, cb) => {
          gotSecondPOST = true;
          cb(null, [200, 'foo']);
        });

      cachedCrypto.key
        .then(k => {
          let client = new TransportClient({accountKey: k});
          client.nonces = ['foo', 'bar'];
          return client.post('https://example.com/foo', {});
        })
        .then(response => {
          assert.equal(response.response.statusCode, 200);
          assert.equal(response.body, 'foo');
          assert.isTrue(gotFirstPOST);
          assert.isTrue(gotSecondPOST);
          done();
        })
        .catch(done);
    };
  }


  it('retries POST when rate-limited (retry-after as int)', testRetryAfter(1));
  it('retries POST when rate-limited (retry-after as date)', testRetryAfter(() => {
    let now = new Date();
    let nowPlus = new Date(now.getTime() + 1000);
    return nowPlus.toUTCString();
  }));
  it('retries POST when rate-limited (retry-after as past date)', testRetryAfter(() => {
    let now = new Date();
    let nowPlus = new Date(now.getTime() - 1000);
    return nowPlus.toUTCString();
  }));
  it('retries POST when rate-limited (invalid retry-after)', testRetryAfter('foo'));

  it('passes on POST errors that are not handed by ACME', (done) => {
    nock('https://example.com')
        .post('/foo').reply(420);

    cachedCrypto.key
      .then(k => {
        let client = new TransportClient({accountKey: k});
        client.nonces = ['foo'];
        return client.post('https://example.com/foo', {});
      })
      .then(() => { done(new Error('Should have gotten error')); })
      .catch(err => {
        assert.equal(err.response.statusCode, 420);
        done();
      });
  });
});
