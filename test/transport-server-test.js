// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert          = require('chai').assert;
const request         = require('supertest');
const https           = require('https');
const MockClient      = require('./tools/mock-client');
const promisify       = require('./tools/promisify');
const cachedCrypto    = require('./tools/cached-crypto');
const TransportServer = require('../lib/server/transport-server');

const port = 4300;
const rateLimit = 5;

const nonceRE = /^[a-zA-Z0-9-_]+$/;
const mockClient = new MockClient();

describe('transport-level server', () => {
  let transport;
  let server;

  beforeEach(done => {
    cachedCrypto.tlsConfig
      .then(tlsConfig => {
        transport = new TransportServer({rateLimit: rateLimit});
        server = https.createServer(tlsConfig, transport.app);
        server.listen(port, done);
      });
  });

  afterEach(done => {
    server.close(done);
  });

  it('responds to a valid POST request', (done) => {
    let nonce = transport.nonces.get();
    let payload = {'fnord': 42};

    let gotPOST = false;
    let result = {'bar': 2};
    transport.app.post('/foo', (req, res) => {
      gotPOST = true;

      try {
        assert.deepEqual(req.payload, payload);
      } catch (e) {
        res.status(418);
      }

      res.json(result);
    });

    mockClient.makeJWS(nonce, 'https://127.0.0.1/foo', payload)
      .then(jws => promisify(request(server).post('/foo').send(jws)))
      .then(res => {
        assert.equal(res.status, 200);

        assert.property(res.headers, 'replay-nonce');
        assert.ok(res.headers['replay-nonce'].match(nonceRE));

        assert.isTrue(gotPOST);
        assert.deepEqual(res.body, result);
        done();
      })
      .catch(done);
  });

  it('refuses a non-HTTPS request', (done) => {
    transport = new TransportServer();
    let httpServer = transport.app.listen(8080, () => {
      request(httpServer)
        .get('/')
        .expect(500, done);
    });
  });

  it('applies a rate limit', (done) => {
    transport.rateLimit.queue.push(new Date('2016-01-01'));
    for (let i = 0; i < rateLimit; ++i) {
      transport.rateLimit.update();
    }

    promisify(request(server).post('/unknown'))
      .then(res => {
        assert.equal(res.status, 403);
        assert.propertyVal(res.headers, 'retry-after', '1');
        done();
      })
      .catch(done);
  });

  it('rejects a POST with a bad nonce', (done) => {
    mockClient.makeJWS('asdf', 'https://127.0.0.1/foo?bar=baz', {})
      .then(jws => {
        request(server)
          .post('/foo?bar=baz')
          .send(jws)
          .expect(400, done);
      });
  });

  it('rejects a POST with a bad url', (done) => {
    let nonce = transport.nonces.get();

    mockClient.makeJWS(nonce, 'https://example.com/stuff', {})
      .then(jws => {
        request(server)
          .post('/foo?bar=baz')
          .send(jws)
          .expect(400, done);
      });
  });

  it('provides a nonce for GET requests', (done) => {
    request(server)
      .get('/')
      .expect(404)
      .expect('replay-nonce', nonceRE, done);
  });

  it('provides a nonce for HEAD requests', (done) => {
    request(server)
      .head('/')
      .expect(404)
      .expect('replay-nonce', nonceRE)
      .end(done);
  });
});
