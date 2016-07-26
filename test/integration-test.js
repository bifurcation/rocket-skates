// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert           = require('chai').assert;
const jose             = require('../lib/jose');
const TransportClient  = require('../lib/transport-client');
const TransportServer  = require('../lib/transport-server');
const HTTP01Challenge  = require('../lib/challenges/http-challenge');
const HTTP01Validation = require('../lib/validations/http-validation');
const DNS01Challenge  = require('../lib/challenges/dns-challenge');
const DNS01Validation = require('../lib/validations/dns-validation');

const PORT = 4430;

describe('transport-level client/server integration', () => {
  it('performs a POST request with preflight', (done) => {
    let server = new TransportServer();

    let url = `http://localhost:${PORT}/foo`;
    let gotPOST = false;
    let query = {'foo': 'bar'};
    let result = {'bar': 2};

    server.app.locals.port = PORT;
    server.app.post('/foo', (req, res) => {
      gotPOST = true;
      assert.deepEqual(req.payload, query);
      res.json(result);
    });

    let httpServer;
    let p = new Promise(res => {
      httpServer = server.app.listen(PORT, () => res());
    });
    p.then(() => { return jose.newkey(); })
      .then(k => {
        let client = new TransportClient({accountKey: k});
        return client.post(url, query);
      })
      .then(response => {
        assert.isTrue(gotPOST);
        assert.deepEqual(response.body, result);
      })
      .then(() => {
        httpServer.close();
        done();
      })
      .catch(done);
  });
});

describe('http-01 challenge/validation integration', () => {
  HTTP01Challenge.port = 8080;
  HTTP01Validation.port = 8080;

  it('completes', (done) => {
    let key;
    let challengeObj;
    let challenge;
    let response;

    jose.newkey()
      .then(k => {
        key = k;
        return key.thumbprint();
      })
      .then(tpBuf => {
        let thumbprint = jose.base64url.encode(tpBuf);
        challengeObj = new HTTP01Challenge('localhost', thumbprint);
        challenge = challengeObj.toJSON();
        return HTTP01Validation.makeResponse(key, challenge);
      })
      .then(res => {
        response = res;

        // On the one side
        let p = new Promise(resolve => {
          HTTP01Validation.respond('localhost', challenge, response, () => {
            resolve(true);
          });
        });

        // On the other side
        return p.then(() => {
          return challengeObj.update(response);
        });
      })
      .then(() => {
        assert.equal(challengeObj.status, 'valid');
        done();
      })
      .catch(done);
  });
});

describe('dns-01 challenge/validation integration', () => {
  DNS01Challenge.port = 5300;
  DNS01Validation.port = 5300;

  it('completes', (done) => {
    let key;
    let challengeObj;
    let challenge;
    let response;

    jose.newkey()
      .then(k => {
        key = k;
        return key.thumbprint();
      })
      .then(tpBuf => {
        let thumbprint = jose.base64url.encode(tpBuf);
        challengeObj = new DNS01Challenge('localhost', thumbprint);
        challenge = challengeObj.toJSON();
        return DNS01Validation.makeResponse(key, challenge);
      })
      .then(res => {
        response = res;

        // On the one side
        let p = new Promise(resolve => {
          DNS01Validation.respond('localhost', challenge, response, () => {
            resolve(true);
          });
        });

        // On the other side
        return p.then(() => {
          return challengeObj.update(response);
        });
      })
      .then(() => {
        assert.equal(challengeObj.status, 'valid');
        done();
      })
      .catch(done);
  });
});
