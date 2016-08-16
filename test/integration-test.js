// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert             = require('chai').assert;
const https              = require('https');
const cachedCrypto       = require('./tools/cached-crypto');
const AutoChallenge      = require('./tools/auto-challenge');
const AutoValidation     = require('./tools/auto-validation');
const jose               = require('../lib/jose');
const pki                = require('../lib/pki');
const TransportClient    = require('../lib/client/transport-client');
const TransportServer    = require('../lib/server/transport-server');
const HTTP01Challenge    = require('../lib/server/http-challenge');
const HTTP01Validation   = require('../lib/client/http-validation');
const DNS01Challenge     = require('../lib/server/dns-challenge');
const DNS01Validation    = require('../lib/client/dns-validation');
const TLSSNI02Challenge  = require('../lib/server/tls-sni-challenge');
const TLSSNI02Validation = require('../lib/client/tls-sni-validation');
const ACMEClient         = require('../lib/client/acme-client');
const ACMEServer         = require('../lib/server/acme-server');

const port = 4430;

describe('transport-level client/server integration', () => {
  let transport;
  let server;

  beforeEach(done => {
    transport = new TransportServer();
    cachedCrypto.tlsConfig
      .then(config => {
        server = https.createServer(config, transport.app);
        server.listen(port, done);
      });
  });

  afterEach(done => {
    server.close(done);
  });

  it('performs a POST request with preflight', (done) => {
    let url = `https://localhost:${port}/foo`;
    let gotPOST = false;
    let query = {'foo': 'bar'};
    let result = {'bar': 2};

    transport.app.locals.port = port;
    transport.app.post('/foo', (req, res) => {
      gotPOST = true;
      assert.deepEqual(req.payload, query);
      res.json(result);
    });

    cachedCrypto.key
      .then(k => {
        let client = new TransportClient({accountKey: k});
        return client.post(url, query);
      })
      .then(response => {
        assert.isTrue(gotPOST);
        assert.deepEqual(response.body, result);
        done();
      })
      .catch(done);
  });
});

function testChallengeValidation(challengeType, validationType) {
  return function(done) {
    let key;
    let challengeObj;
    let challenge;
    let response;

    cachedCrypto.key
      .then(k => {
        key = k;
        return key.thumbprint();
      })
      .then(tpBuf => {
        let thumbprint = jose.base64url.encode(tpBuf);
        challengeObj = new challengeType('localhost', thumbprint);
        challenge = challengeObj.toJSON();
        return validationType.makeResponse(key, challenge);
      })
      .then(res => {
        response = res;

        // On the client side
        let p = new Promise(resolve => {
          validationType.respond('localhost', challenge, response, () => {
            resolve(true);
          });
        });

        // On the server side
        return p.then(() => {
          return challengeObj.update(response);
        });
      })
      .then(() => {
        assert.equal(challengeObj.status, 'valid');
        done();
      })
      .catch(done);
  };
}

describe('challenge/validation integration', () => {
  HTTP01Challenge.port    = 8080;
  HTTP01Validation.port   = 8080;
  DNS01Challenge.port     = 5300;
  DNS01Validation.port    = 5300;
  TLSSNI02Challenge.port  = 4430;
  TLSSNI02Validation.port = 4430;

  it('http-01', testChallengeValidation(HTTP01Challenge, HTTP01Validation));
  it('dns-01', testChallengeValidation(DNS01Challenge, DNS01Validation));
  it('tls-sni-02', testChallengeValidation(TLSSNI02Challenge, TLSSNI02Validation));
});

describe('ACME-level client/server integration', () => {
  let httpsServer;
  let acmeServer;
  let acmeClient;

  let localCA = new pki.CA();
  const acmeServerConfig = {
    host:           '127.0.0.1',
    port:           port,
    challengeTypes: [AutoChallenge],
    CA:             localCA
  };
  const acmeClientConfig = {
    accountKey:      null,
    directoryURL:    `https://127.0.0.1:${port}/directory`,
    validationTypes: [AutoValidation]
  };

  before(function(done) {
    this.timeout(10000);
    localCA.keys()
      .then(() => { done(); })
      .catch(done);
  });

  beforeEach((done) => {
    acmeServer = new ACMEServer(acmeServerConfig);
    cachedCrypto.key
      .then(k => {
        acmeClientConfig.accountKey = k;
        acmeClient = new ACMEClient(acmeClientConfig);
        return cachedCrypto.tlsConfig;
      })
      .then(config => {
        httpsServer = https.createServer(config, acmeServer.app);
        return httpsServer.listen(port, done);
      })
      .catch(done);
  });

  afterEach(done => {
    httpsServer.close(done);
  });

  it('fetches the directory', (done) => {
    acmeClient.directory()
      .then(dir => {
        assert.isObject(dir);
        done();
      })
      .catch(done);
  });

  it('registers an account key', (done) => {
    let contact = ['mailto:someone@example.com'];
    acmeClient.register(contact)
      .then(response => {
        assert.equal(response.response.statusCode, 201);
        assert.property(response.body, 'key');
        assert.deepEqual(response.body.key, acmeClient.client.accountKey.toJSON());
        assert.property(response.body, 'contact');
        assert.deepEqual(response.body.contact, contact);
        done();
      })
      .catch(done);
  });

  it('requests a certificate', (done) => {
    let contact = ['mailto:someone@example.com'];
    acmeClient.register(contact)
      .then(() => {
        acmeClient.requestCertificate(cachedCrypto.certReq.csr,
                                      cachedCrypto.certReq.notBefore,
                                      cachedCrypto.certReq.notAfter)
          .then(() => {
            done();
          });
      })
      .catch(done);
  });
});
