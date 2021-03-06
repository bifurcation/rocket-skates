// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert              = require('chai').assert;
const request             = require('supertest');
const urlParse            = require('url').parse;
const https               = require('https');
const forge               = require('node-forge');
const nodeJose            = require('node-jose');
const Promise             = require('bluebird');
const MockClient          = require('./tools/mock-client');
const AutoChallenge       = require('./tools/auto-challenge');
const promisify           = require('./tools/promisify');
const cachedCrypto        = require('./tools/cached-crypto');
const jose                = require('../lib/jose');
const pki                 = require('../lib/pki');
const ACMEServer          = require('../lib/server/acme-server');

let localCA = new pki.CA();
let mockClient = new MockClient();
let mockClient2 = new MockClient();

const serverConfig = {
  host:               '127.0.0.1',
  port:               443, // NB: This is a lie
  authzExpirySeconds: 30 * 24 * 3600,
  challengeTypes:     [AutoChallenge],
  oobHandlers:        [(req, res) => {
    res.end();
    return Promise.resolve(true);
  }],
  CA: localCA
};
const port = 4430;

class NotAChallenge {}

function path(url) {
  return urlParse(url).path;
}

function registerKey(key, server) {
  let thumbprint;
  return key.thumbprint()
    .then(tpBuffer => {
      thumbprint = jose.base64url.encode(tpBuffer);
      let existing = {
        id:         thumbprint,
        thumbprint: thumbprint,
        key:        key,
        contact:    ['mailto:anonymous@example.com'],
        type:       function() { return 'reg'; },
        marshal:    function() {
          return {
            key:       this.key.toJSON(),
            status:    this.status,
            contact:   this.contact,
            agreement: this.agreement
          };
        }
      };
      existing.url = server.makeURL(existing);
      server.db.put(existing);
      return thumbprint;
    });
}

describe('ACME server', () => {
  let httpsServer;
  let acmeServer;
  let testServer;

  before(function(done) {
    this.timeout(15000);
    localCA.keys()
      .then(() => { mockClient.key(); })
      .then(() => { mockClient2.key(); })
      .then(() => { done(); })
      .catch(done);
  });

  beforeEach((done) => {
    cachedCrypto.tlsConfig
      .then(tlsConfig => {
        acmeServer = new ACMEServer(serverConfig);
        httpsServer = https.createServer(tlsConfig, acmeServer.app);
        testServer = request(httpsServer);
        httpsServer.listen(port, done);
      });
  });

  afterEach(done => {
    httpsServer.close(done);
  });

  it('refuses to create a server with no challenges', (done) => {
    try {
      new ACMEServer({challengeTypes: []});
      done(new Error('Created a server with a bogus challenge'));
    } catch (e) {
      done();
    }
  });

  it('refuses to create a server with bad challenges', (done) => {
    try {
      new ACMEServer({challengeTypes: [NotAChallenge]});
      done(new Error('Created a server with a bogus challenge'));
    } catch (e) {
      done();
    }
  });

  it('responds to a directory request', (done) => {
    acmeServer.terms = 'https://example.com/terms';

    promisify(testServer.get('/directory'))
      .then(res => {
        assert.equal(res.status, 200);

        assert.property(res.headers, 'content-type');
        assert.include(res.headers['content-type'], 'application/json');

        assert.property(res.body, 'meta');
        assert.isObject(res.body.meta);
        assert.property(res.body.meta, 'terms-of-service');
        assert.equal(res.body.meta['terms-of-service'], acmeServer.terms);

        // Add things here as they get added to the directory
        assert.property(res.body, 'new-reg');
        assert.property(res.body, 'new-app');

        done();
      })
      .catch(done);
  });

  it('answers a valid fetch', (done) => {
    let reg = {
      type:        function() { return 'foo'; },
      id:          'bar',
      marshal:     function() { return {baz: 42}; },
      contentType: function() { return 'application/json'; }
    };

    acmeServer.db.put(reg);
    promisify(testServer.get('/foo/bar'))
      .then(res => {
        assert.equal(res.status, 200);
        assert.deepEqual(res.body, reg.marshal());
        assert.property(res.headers, 'content-type');
        assert.include(res.headers['content-type'], 'application/json');
        done();
      })
      .catch(done);
  });

  it('rejects a fetch for a registration object', (done) => {
    testServer
      .get('/reg/foo')
      .expect(401, done);
  });

  it('rejects a fetch for a non-existent object', (done) => {
    testServer
      .get('/foo/bar')
      .expect(404, done);
  });

  it('creates a new registration', (done) => {
    acmeServer.terms = 'https://example.com/terms';

    let nonce = acmeServer.transport.nonces.get();
    let url = acmeServer.baseURL + '/new-reg';
    let reg = {contact: ['mailto:anonymous@example.com']};
    let regPath;
    let created;

    mockClient.makeJWS(nonce, url, reg)
      .then(jws => promisify(testServer.post('/new-reg').send(jws)))
      .then(res => {
        assert.equal(res.status, 201);
        assert.property(res.headers, 'content-type');
        assert.include(res.headers['content-type'], 'application/json');

        assert.property(res.headers, 'location');
        assert.property(res.headers, 'replay-nonce');
        assert.property(res.headers, 'link');

        created = res.body;
        assert.property(created, 'key');
        assert.property(created, 'contact');
        assert.deepEqual(created.key, mockClient._key.toJSON());
        assert.deepEqual(created.contact, reg.contact);

        regPath = path(res.headers.location);
        let newNonce = res.headers['replay-nonce'];
        return mockClient.makeJWS(newNonce, res.headers.location, {});
      })
      .then(jws => promisify(testServer.post(regPath).send(jws)))
      .then(res => {
        assert.equal(res.status, 200);
        assert.deepEqual(res.body, created);
        done();
      })
      .catch(done);
  });

  it('constructs a server with a custom port', () => {
    let server = new ACMEServer({
      host:           '127.0.0.1',
      port:           8080,
      challengeTypes: [AutoChallenge]
    });

    assert.equal(server.baseURL, 'https://127.0.0.1:8080');
  });

  it('rejects a new registration for an existing key', (done) => {
    let nonce = acmeServer.transport.nonces.get();
    let url = acmeServer.baseURL + '/new-reg';
    let reg = {contact: ['mailto:anonymous@example.com']};
    let jws;

    mockClient.makeJWS(nonce, url, reg)
      .then(signed => {
        jws = signed;
        return mockClient._key.thumbprint();
      })
      .then(tpBuffer => {
        let existing = {
          thumbprint: jose.base64url.encode(tpBuffer),
          type:       function() { return 'reg'; }
        };
        acmeServer.db.put(existing);

        request(httpsServer)
          .post('/new-reg')
          .send(jws)
          .expect(409)
          .expect('location', /.*/, done);
      });
  });

  it('updates a registration', (done) => {
    let termsURL = 'https://example.com/terms';
    acmeServer.terms = termsURL;

    let reg2 = {
      contact:   ['mailto:someone@example.com'],
      agreement: termsURL
    };
    let regThumbprint;

    mockClient.key()
      .then(k => registerKey(k, acmeServer))
      .then(thumbprint => {
        regThumbprint = thumbprint;
        let nonce = acmeServer.transport.nonces.get();
        let url = `${acmeServer.baseURL}/reg/${regThumbprint}`;
        return mockClient.makeJWS(nonce, url, reg2);
      })
      .then(jws => promisify(request(httpsServer).post(`/reg/${regThumbprint}`).send(jws)))
      .then(res => {
        assert.equal(res.status, 200);

        assert.property(res.body, 'key');
        assert.property(res.body, 'contact');
        assert.property(res.body, 'agreement');

        assert.deepEqual(res.body.key, mockClient._key.toJSON());
        assert.deepEqual(res.body.contact, reg2.contact);
        assert.deepEqual(res.body.agreement, reg2.agreement);
        done();
      })
      .catch(done);
  });

  it('deactivates an account', (done) => {
    let regPath;

    mockClient.key()
      .then(k => registerKey(k, acmeServer))
      .then(thumbprint => {
        regPath = `/reg/${thumbprint}`;
        let nonce = acmeServer.transport.nonces.get();
        let url = `${acmeServer.baseURL}${regPath}`;
        return mockClient.makeJWS(nonce, url, {status: 'deactivated'});
      })
      .then(jws => promisify(request(httpsServer).post(regPath).send(jws)))
      .then(res => {
        assert.equal(res.status, 200);
        let nonce = acmeServer.transport.nonces.get();
        let url = `${acmeServer.baseURL}${regPath}`;
        return mockClient.makeJWS(nonce, url, {});
      })
      .then(jws => promisify(request(httpsServer).post(regPath).send(jws)))
      .then(res => {
        assert.equal(res.status, 404);
        done();
      })
      .catch(done);
  });

  it('rejects a registration update to a non-existent registration', (done) => {
    let nonce = acmeServer.transport.nonces.get();
    let url = `${acmeServer.baseURL}/reg/non-existent`;

    mockClient.makeJWS(nonce, url, {})
      .then(jws => {
        return promisify(request(httpsServer).post('/reg/non-existent').send(jws));
      })
      .then(res => {
        assert.equal(res.status, 404);
        done();
      })
      .catch(done);
  });

  it('rejects a registration update with the wrong key', (done) => {
    let regThumbprint;
    cachedCrypto.key
      .then(k => registerKey(k, acmeServer))
      .then(thumbprint => {
        regThumbprint = thumbprint;
        let url = `${acmeServer.baseURL}/reg/${regThumbprint}`;
        let nonce = acmeServer.transport.nonces.get();
        return mockClient.makeJWS(nonce, url, {});
      })
      .then(jws => {
        return promisify(request(httpsServer).post(`/reg/${regThumbprint}`).send(jws));
      })
      .then(res => {
        assert.equal(res.status, 401);
        done();
      })
      .catch(done);
  });

  it('rejects a registration update with the wrong terms', (done) => {
    let termsURL = 'https://example.com/terms';
    acmeServer.terms = termsURL;

    let regThumbprint;
    let reg2 = {
      contact:   ['mailto:someone@example.org'],
      agreement: termsURL + '-not!'
    };

    mockClient.key()
      .then(k => registerKey(k, acmeServer))
      .then(thumbprint => {
        regThumbprint = thumbprint;
        let nonce = acmeServer.transport.nonces.get();
        let url = `${acmeServer.baseURL}/reg/${regThumbprint}`;
        return mockClient.makeJWS(nonce, url, reg2);
      })
      .then(jws => promisify(request(httpsServer).post(`/reg/${regThumbprint}`).send(jws)))
      .then(res => {
        assert.equal(res.status, 400);
        done();
      })
      .catch(done);
  });

  it('creates a new application', (done) => {
    let app = {
      'csr':       cachedCrypto.certReq.csr,
      'notBefore': cachedCrypto.certReq.notBefore,
      'notAfter':  cachedCrypto.certReq.notAfter
    };

    mockClient.key()
      .then(k => registerKey(k, acmeServer))
      .then(() => {
        let nonce = acmeServer.transport.nonces.get();
        let url = acmeServer.baseURL + '/new-app';
        return mockClient.makeJWS(nonce, url, app);
      })
      .then(jws => promisify(testServer.post('/new-app').send(jws)))
      .then(res => {
        assert.equal(res.status, 201);

        assert.property(res.headers, 'location');

        assert.property(res.body, 'status');
        assert.property(res.body, 'csr');
        assert.property(res.body, 'notBefore');
        assert.property(res.body, 'notAfter');
        assert.property(res.body, 'requirements');

        assert.equal(res.body.csr, app.csr);
        assert.equal(res.body.notBefore, app.notBefore.toJSON());
        assert.equal(res.body.notAfter, app.notAfter.toJSON());
        assert.isArray(res.body.requirements);
        assert.isTrue(res.body.requirements.length > 0);

        let gotAuthz = false;
        let gotOOB = false;
        let authz = res.body.requirements.map(req => {
          if (req.type === 'authorization') {
            gotAuthz = true;
            let authzPath = path(req.url);
            return promisify(testServer.get(authzPath));
          }

          if (req.type === 'out-of-band') {
            gotOOB = true;
            let oobPath = path(req.url);
            return promisify(testServer.get(oobPath))
              .then(oobRes => {
                assert.equal(oobRes.status, 200);
              });
          }

          let err = new Error('Unknown requirement type: ' + req.type);
          return Promise.reject(err);
        });

        assert.isTrue(gotAuthz);
        assert.isTrue(gotOOB);
        return Promise.all(authz);
      })
      .then(responses => {
        let challengeTests = [];
        let authzNames = [];
        responses.map(res => {
          if (!res) {
            return;
          }
          assert.equal(res.status, 200);

          assert.property(res.body, 'status');
          assert.property(res.body, 'expires');
          assert.property(res.body, 'identifier');
          assert.property(res.body, 'challenges');

          assert.isString(res.body.status);
          assert.isNotNaN((new Date(res.body.expires)).getTime());

          assert.property(res.body.identifier, 'type');
          assert.property(res.body.identifier, 'value');
          assert.propertyVal(res.body.identifier, 'type', 'dns');
          assert.isString(res.body.identifier.value);
          authzNames.push(res.body.identifier.value);

          assert.isArray(res.body.challenges);
          res.body.challenges.map(chall => {
            assert.isObject(chall);
            assert.property(chall, 'type');
            assert.property(chall, 'url');
            assert.isString(chall.type);
            assert.isString(chall.url);

            let challPath = path(chall.url);
            let test = promisify(testServer.get(challPath))
              .then(res2 => {
                assert.equal(res2.status, 200);
                assert.deepEqual(res2.body, chall);
              });
            challengeTests.push(test);
          });
        });

        assert.deepEqual(authzNames.sort(), cachedCrypto.certReq.names.sort());
        return Promise.all(challengeTests);
      })
      .then(() => { done(); })
      .catch(done);
  });

  it('invalidates OOB requirements', (done) => {
    let app = {
      'csr':       cachedCrypto.certReq.csr,
      'notBefore': cachedCrypto.certReq.notBefore,
      'notAfter':  cachedCrypto.certReq.notAfter
    };

    acmeServer.oobHandlers = [(req, res) => {
      res.end();
      return Promise.reject(new Error());
    }];

    let appPath;
    mockClient.key()
      .then(k => registerKey(k, acmeServer))
      .then(() => {
        let nonce = acmeServer.transport.nonces.get();
        let url = acmeServer.baseURL + '/new-app';
        return mockClient.makeJWS(nonce, url, app);
      })
      .then(jws => promisify(testServer.post('/new-app').send(jws)))
      .then(res => {
        assert.equal(res.status, 201);

        appPath = path(res.headers.location);

        let gets = [];
        res.body.requirements.map(req => {
          if (req.type !== 'out-of-band') {
            return;
          }

          let oobPath = path(req.url);
          gets.push(promisify(testServer.get(oobPath)));
        });

        return Promise.all(gets);
      })
      .then(() => { return promisify(testServer.get(appPath)); })
      .then(res => {
        assert.equal(res.status, 200);

        res.body.requirements.map(req => {
          if (req.type === 'out-of-band') {
            assert.equal(req.status, 'invalid');
          }
        });
        done();
      })
      .catch(done);
  });

  it('expires an authorization', (done) => {
    let app = {'csr': cachedCrypto.certReq.csr};

    mockClient.key()
      .then(k => registerKey(k, acmeServer))
      .then(() => {
        let nonce = acmeServer.transport.nonces.get();
        let url = acmeServer.baseURL + '/new-app';
        return mockClient.makeJWS(nonce, url, app);
      })
      .then(jws => promisify(testServer.post('/new-app').send(jws)))
      .then(res => {
        assert.equal(res.status, 201);

        let authzURL = res.body.requirements[0].url;
        let authzPath = path(authzURL);
        let authzID = authzPath.replace(/^.*\//, '');
        let authz = acmeServer.db.get('authz', authzID);

        authz.expires = new Date('2015-01-01T00:00:00Z');
        acmeServer.db.put(authz);

        return testServer.get(authzPath);
      })
      .then(res => {
        assert.equal(res.status, 200);
        assert.equal(res.body.status, 'invalid');
        done();
      })
      .catch(done);
  });

  it('rejects a fetch to a bad challenge URL', (done) => {
    let app = {
      'csr':       cachedCrypto.certReq.csr,
      'notBefore': cachedCrypto.certReq.notBefore,
      'notAfter':  cachedCrypto.certReq.notAfter
    };

    mockClient.key()
      .then(k => registerKey(k, acmeServer))
      .then(() => {
        let nonce = acmeServer.transport.nonces.get();
        let url = acmeServer.baseURL + '/new-app';
        return mockClient.makeJWS(nonce, url, app);
      })
      .then(jws => promisify(testServer.post('/new-app').send(jws)))
      .then(res => {
        assert.equal(res.status, 201);
        assert.equal(res.body.requirements[0].type, 'authorization');

        let badChallengePath = path(res.body.requirements[0].url) + '/42';
        return promisify(testServer.get(badChallengePath));
      })
      .then(res => {
        assert.equal(res.status, 404);
        done();
      })
      .catch(done);
  });

  it('rejects a new application from an unregistered key', (done) => {
    let nonce = acmeServer.transport.nonces.get();
    let url = acmeServer.baseURL + '/new-app';

    mockClient.makeJWS(nonce, url, {})
      .then(jws => {
        return promisify(testServer.post('/new-app').send(jws));
      })
      .then(res => {
        assert.equal(res.status, 401);
        done();
      })
      .catch(done);
  });

  function newAppError(app) {
    return (done) => {
      mockClient.key()
        .then(k => registerKey(k, acmeServer))
        .then(() => {
          let nonce = acmeServer.transport.nonces.get();
          let url = acmeServer.baseURL + '/new-app';
          return mockClient.makeJWS(nonce, url, app);
        })
        .then(jws => promisify(testServer.post('/new-app').send(jws)))
        .then(res => {
          assert.equal(res.status, 400);
          done();
        })
        .catch(done);
    };
  }

  it('rejects a new application with an no csr', newAppError({}));

  it('rejects a new application with an invalid csr', newAppError({
    csr: cachedCrypto.certReq.csr.substr(0, 5)
  }));

  it('rejects a new application with an invalid notBefore', newAppError({
    csr:       cachedCrypto.certReq.csr,
    notBefore: 'not-a-date'
  }));

  it('rejects a new application with notAfter without notBefore', newAppError({
    csr:      cachedCrypto.certReq.csr,
    notAfter: cachedCrypto.certReq.notAfter
  }));

  it('rejects a new application with an invalid notAfter', newAppError({
    csr:       cachedCrypto.certReq.csr,
    notBefore: cachedCrypto.certReq.notBefore,
    notAfter:  'not-a-date'
  }));

  it('rejects a new application with an excessive lifetime', newAppError({
    csr:       cachedCrypto.certReq.csr,
    notBefore: cachedCrypto.certReq.notBefore,
    notAfter:  new Date(cachedCrypto.certReq.notBefore.getTime() +
                        20 * 365 * 24 * 60 * 60 * 1000)
  }));

  it('issues a certificate', function(done) {
    this.timeout(10000);

    let app = {
      'csr':       cachedCrypto.certReq.csr,
      'notBefore': cachedCrypto.certReq.notBefore,
      'notAfter':  cachedCrypto.certReq.notAfter
    };

    let appPath;
    mockClient.key()
      .then(k => registerKey(k, acmeServer))
      .then(() => {
        let nonce = acmeServer.transport.nonces.get();
        let url = acmeServer.baseURL + '/new-app';
        return mockClient.makeJWS(nonce, url, app);
      })
      .then(jws => promisify(testServer.post('/new-app').send(jws)))
      .then(res => {
        assert.equal(res.status, 201);

        appPath = path(res.headers.location);

        let validations = res.body.requirements
          .filter(x => (x.type === 'authorization'))
          .map(req => {
            let authzPath = path(req.url);
            let challPath;

            return Promise.resolve()
              .then(() => promisify(testServer.get(authzPath)))
              .then(authzRes => {
                assert.equal(authzRes.status, 200);

                let challURL = authzRes.body.challenges[0].url;
                challPath = path(challURL);
                let challNonce = acmeServer.transport.nonces.get();
                return mockClient.makeJWS(challNonce, challURL, {
                  type:  AutoChallenge.type,
                  token: authzRes.body.challenges[0].token
                });
              })
              .then(jws =>  promisify(testServer.post(challPath).send(jws)))
              .then(challRes => {
                assert.equal(challRes.status, 200);
              })
              .then(() => promisify(testServer.get(authzPath)))
              .then(authzRes => {
                assert.equal(authzRes.status, 200);
                assert.equal(authzRes.body.status, 'valid');
              });
          });

        res.body.requirements.filter(x => (x.type === 'out-of-band'))
          .map(req => {
            let oobPath = path(req.url);
            validations.push(promisify(testServer.get(oobPath)));
          });

        return Promise.all(validations);
      })
      .then(() => promisify(testServer.get(appPath)))
      .then(res => {
        assert.equal(res.status, 200);
        assert.equal(res.body.status, 'valid');
        assert.property(res.body, 'certificate');
        assert.isString(res.body.certificate);

        let certPath = path(res.body.certificate);
        return promisify(testServer.get(certPath));
      })
      .then(res => {
        assert.equal(res.status, 200);

        assert.property(res.headers, 'content-type');
        assert.include(res.headers['content-type'], 'application/pkix-cert');
        // XXX(#22): Test that the returned value is a valid certificate

        done();
      })
      .catch(done);
  });

  it('re-uses authorizations for the same client', (done) => {
    let app = {
      'csr':       cachedCrypto.certReq.csr,
      'notBefore': cachedCrypto.certReq.notBefore,
      'notAfter':  cachedCrypto.certReq.notAfter
    };

    let authzURL;
    mockClient.key()
      .then(k => registerKey(k, acmeServer))
      .then(() => {
        let nonce = acmeServer.transport.nonces.get();
        let url = acmeServer.baseURL + '/new-app';
        return mockClient.makeJWS(nonce, url, app);
      })
      .then(jws => promisify(testServer.post('/new-app').send(jws)))
      .then(res => {
        assert.equal(res.status, 201);
        authzURL = res.body.requirements[0].url;

        let nonce = acmeServer.transport.nonces.get();
        let url = acmeServer.baseURL + '/new-app';
        return mockClient.makeJWS(nonce, url, app);
      })
      .then(jws => promisify(testServer.post('/new-app').send(jws)))
      .then(res => {
        assert.equal(res.status, 201);
        assert.equal(res.body.requirements[0].url, authzURL);
        done();
      })
      .catch(done);
  });

  it('ignores applications from a different registration', (done) => {
    let app = {
      'csr':       cachedCrypto.certReq.csr,
      'notBefore': cachedCrypto.certReq.notBefore,
      'notAfter':  cachedCrypto.certReq.notAfter
    };

    let bogusApp = {
      id:      'not-your-id',
      regID:   'not-your-id',
      type:    function() { return 'app'; },
      touched: false,

      get challenges() {
        this.touched = true;
        return [];
      }
    };
    acmeServer.db.put(bogusApp);

    let appPath;
    mockClient.key()
      .then(k => registerKey(k, acmeServer))
      .then(() => {
        let nonce = acmeServer.transport.nonces.get();
        let url = acmeServer.baseURL + '/new-app';
        return mockClient.makeJWS(nonce, url, app);
      })
      .then(jws => promisify(testServer.post('/new-app').send(jws)))
      .then(res => {
        assert.equal(res.status, 201);

        appPath = path(res.headers.location);
        let authzPath = path(res.body.requirements[0].url);
        return testServer.get(authzPath);
      })
      .then(res => {
        assert.equal(res.status, 200);

        let nonce = acmeServer.transport.nonces.get();
        let url = res.body.challenges[0].url;
        return mockClient.makeJWS(nonce, url, app)
          .then(jws => promisify(testServer.post(path(url)).send(jws)));
      })
      .then(() => promisify(testServer.get(appPath)))
      .then(() => {
        assert.isFalse(bogusApp.touched);
        done();
      })
      .catch(done);
  });

  it('rejects an update to a non-existent authz', (done) => {
    let nonce = acmeServer.transport.nonces.get();
    let url = acmeServer.baseURL + '/authz/bogus/0';
    mockClient.makeJWS(nonce, url, {})
      .then(jws => promisify(testServer.post('/authz/bogus/0').send(jws)))
      .then(res => {
        assert.equal(res.status, 404);
        done();
      })
      .catch(done);
  });

  it('rejects an update to an authz by the wrong key', (done) => {
    let challPath;
    cachedCrypto.key
      .then(k => registerKey(k, acmeServer))
      .then(thumbprint => {
        let existing = {
          id:         thumbprint,
          regID:      thumbprint,
          challenges: [null],
          type:       function() { return 'authz'; }
        };
        acmeServer.db.put(existing);

        challPath = `/authz/${thumbprint}/0`;

        let nonce = acmeServer.transport.nonces.get();
        let url = `${acmeServer.baseURL}${challPath}`;
        return mockClient.makeJWS(nonce, url, {});
      })
      .then(jws => promisify(testServer.post(challPath).send(jws)))
      .then(res => {
        assert.equal(res.status, 401);
        done();
      })
      .catch(done);
  });

  it('rejects an update to a finalized authz', (done) => {
    let challPath;
    mockClient.key()
      .then(k => registerKey(k, acmeServer))
      .then(thumbprint => {
        let existing = {
          id:         thumbprint,
          regID:      thumbprint,
          status:     'invalid',
          challenges: [null],
          type:       function() { return 'authz'; },
          marshal:    function() { return ''; }
        };
        acmeServer.db.put(existing);

        challPath = `/authz/${thumbprint}/0`;

        let nonce = acmeServer.transport.nonces.get();
        let url = `${acmeServer.baseURL}${challPath}`;
        return mockClient.makeJWS(nonce, url, {});
      })
      .then(jws => promisify(testServer.post(challPath).send(jws)))
      .then(res => {
        assert.equal(res.status, 403);
        done();
      })
      .catch(done);
  });

  it('rejects an update to a non-existent challenge', (done) => {
    let challPath;
    mockClient.key()
      .then(k => registerKey(k, acmeServer))
      .then(thumbprint => {
        let existing = {
          id:         thumbprint,
          regID:      thumbprint,
          status:     'pending',
          challenges: [null],
          type:       function() { return 'authz'; }
        };
        acmeServer.db.put(existing);

        challPath = `/authz/${thumbprint}/5`;

        let nonce = acmeServer.transport.nonces.get();
        let url = `${acmeServer.baseURL}${challPath}`;
        return mockClient.makeJWS(nonce, url, {});
      })
      .then(jws => promisify(testServer.post(challPath).send(jws)))
      .then(res => {
        assert.equal(res.status, 404);
        done();
      })
      .catch(done);
  });

  it('deactivates an authorization', (done) => {
    let authzPath;
    mockClient.key()
      .then(k => registerKey(k, acmeServer))
      .then(thumbprint => {
        let existing = {
          id:          thumbprint,
          regID:       thumbprint,
          challenges:  [null],
          status:      'valid',
          type:        function() { return 'authz'; },
          contentType: function() { return 'application/json'; },
          marshal:     function() { return { status: this.status }; }
        };
        acmeServer.db.put(existing);

        authzPath = `/authz/${thumbprint}`;

        let nonce = acmeServer.transport.nonces.get();
        let url = `${acmeServer.baseURL}${authzPath}`;
        return mockClient.makeJWS(nonce, url, {status: 'deactivated'});
      })
      .then(jws => promisify(testServer.post(`${authzPath}`).send(jws)))
      .then(res => {
        assert.equal(res.status, 200);
        assert.equal(res.body.status, 'deactivated');
        done();
      })
      .catch(done);
  });

  it('changes the key for an account', (done) => {
    let oldKey;
    let oldKeyThumbprint;
    let newKey;
    let newKeyThumbprint;
    let regPath;
    let regURL;

    let keyChangeURL = `${acmeServer.baseURL}/key-change`;

    mockClient2.key()
      .then(k => {
        oldKey = k;
        return registerKey(k, acmeServer);
      })
      .then(thumbprint => {
        oldKeyThumbprint = thumbprint;
        return mockClient.key();
      })
      .then(k => {
        newKey = k;
        return newKey.thumbprint();
      })
      .then(tpBuf => {
        newKeyThumbprint = jose.base64url.encode(tpBuf);

        regPath = `/reg/${oldKeyThumbprint}`;
        regURL = `${acmeServer.baseURL}${regPath}`;
        let keyChangeRequest = {
          account: regURL,
          oldKey:  oldKeyThumbprint,
          newKey:  newKeyThumbprint
        };
        let header = {
          url:   keyChangeURL,
          nonce: 'ignored'
        };

        return jose.sign(oldKey, keyChangeRequest, header);
      })
      .then(innerJWS => {
        let nonce = acmeServer.transport.nonces.get();
        return mockClient.makeJWS(nonce, keyChangeURL, innerJWS);
      })
      .then(outerJWS => promisify(testServer.post('/key-change').send(outerJWS)))
      .then(res => {
        assert.equal(res.status, 200);

        let nonce = acmeServer.transport.nonces.get();
        return mockClient.makeJWS(nonce, regURL, {});
      })
      .then(jws => promisify(testServer.post(regPath).send(jws)))
      .then(res => {
        assert.equal(res.status, 200);
        assert.deepEqual(res.body.key, newKey.toJSON());
        done();
      })
      .catch(done);
  });

  // testCase in ['unregistered', 'badURL', 'badOldKey', 'badNewKey', 'badReg']
  function keyChangeError(testCase) {
    return (done) => {
      let oldKey;
      let oldKeyThumbprint;
      let newKey;
      let newKeyThumbprint;
      let regPath;
      let regURL;

      let keyChangeURL = `${acmeServer.baseURL}/key-change`;

      mockClient2.key()
        .then(k => {
          oldKey = k;
          if (testCase === 'unregistered') {
            return oldKey.thumbprint();
          }

          return registerKey(k, acmeServer);
        })
        .then(thumbprint => {
          oldKeyThumbprint = thumbprint;
          return mockClient.key();
        })
        .then(k => {
          newKey = k;
          return newKey.thumbprint();
        })
        .then(tpBuf => {
          newKeyThumbprint = jose.base64url.encode(tpBuf);

          let urlVal = (testCase === 'badURL')? 'bogus' : keyChangeURL;
          let oldKeyVal = (testCase === 'badOldKey')? 'bogus' : oldKeyThumbprint;
          let newKeyVal = (testCase === 'badNewKey')? 'bogus' : newKeyThumbprint;
          let regVal = (testCase === 'badReg')? 'bogus' : regURL;

          regPath = `/reg/${oldKeyThumbprint}`;
          regURL = `${acmeServer.baseURL}${regPath}`;
          let keyChangeRequest = {
            account: regVal,
            oldKey:  oldKeyVal,
            newKey:  newKeyVal
          };
          let header = {
            url:   urlVal,
            nonce: 'ignored'
          };

          return jose.sign(oldKey, keyChangeRequest, header);
        })
        .then(innerJWS => {
          let nonce = acmeServer.transport.nonces.get();
          return mockClient.makeJWS(nonce, keyChangeURL, innerJWS);
        })
        .then(outerJWS => promisify(testServer.post('/key-change').send(outerJWS)))
        .then(res => {
          assert.equal(res.status, 403);
          done();
        })
        .catch(done);
    };
  }

  it('rejects a key-change request when the old key is unrecognized', keyChangeError('unregistered'));
  it('rejects a key-change request when "url" field is bad',          keyChangeError('badURL'));
  it('rejects a key-change request when "oldKey" field is bad',       keyChangeError('badOldKey'));
  it('rejects a key-change request when "newKey" field is bad',       keyChangeError('badNewKey'));
  it('rejects a key-change request when "account" field is bad',      keyChangeError('badReg'));

  it('revokes a certificate when authorized by the account key', (done) => {
    let certDER = cachedCrypto.certReq.cert;
    let reason = 3;
    let certPath;
    let revokePath = '/revoke-cert';

    mockClient.key()
      .then(k => registerKey(k, acmeServer))
      .then(thumbprint => {
        let cert = {
          id:          thumbprint,
          regID:       thumbprint,
          der:         certDER,
          type:        function() { return 'cert'; },
          marshal:     function() { return this.der; },
          contentType: function() { return 'application/pkix-cert'; }
        };
        acmeServer.db.put(cert);

        certPath = `/cert/${cert.id}`;

        let revocationRequest = {
          certificate: jose.base64url.encode(certDER),
          reason:      reason
        };
        let url = acmeServer.baseURL + revokePath;
        let nonce = acmeServer.transport.nonces.get();
        return mockClient.makeJWS(nonce, url, revocationRequest);
      })
      .then(jws => promisify(testServer.post(revokePath).send(jws)))
      .then(res => {
        assert.equal(res.status, 200);
        return promisify(testServer.get(certPath));
      })
      .then(res => {
        assert.equal(res.status, 200);
        assert.property(res.headers, 'revocation-reason');
        assert.equal(parseInt(res.headers['revocation-reason']), reason);
        done();
      })
      .catch(done);
  });

  it('revokes a certificate when authorized by another account key', (done) => {
    let certDER = cachedCrypto.certReq.cert;
    let reason = 3;
    let revokePath = '/revoke-cert';

    mockClient.key()
      .then(k => registerKey(k, acmeServer))
      .then(thumbprint => {
        let notThumbprint = 'not-' + thumbprint;

        cachedCrypto.certReq.names.map(name => {
          acmeServer.db.put({
            id:         thumbprint + name,
            regID:      thumbprint,
            identifier: { type: 'dns', value: name },
            type:       function() { return 'authz'; }
          });
        });

        let cert = {
          id:          notThumbprint,
          thumbprint:  notThumbprint,
          der:         certDER,
          type:        function() { return 'cert'; },
          marshal:     function() { return this.der; },
          contentType: function() { return 'application/pkix-cert'; }
        };
        acmeServer.db.put(cert);

        let revocationRequest = {
          certificate: jose.base64url.encode(certDER),
          reason:      reason
        };
        let url = acmeServer.baseURL + revokePath;
        let nonce = acmeServer.transport.nonces.get();
        return mockClient.makeJWS(nonce, url, revocationRequest);
      })
      .then(jws => promisify(testServer.post(revokePath).send(jws)))
      .then(res => {
        assert.equal(res.status, 200);
        done();
      })
      .catch(done);
  });

  it('revokes a certificate when authorized by the certificate key', (done) => {
    let certDER = cachedCrypto.certReq.cert;
    let reason = 3;
    let revokePath = '/revoke-cert';

    let privASN1 = forge.pki.privateKeyToAsn1(cachedCrypto.certReq.privateKey);
    let pkcs8Bytes = forge.asn1.toDer(forge.pki.wrapRsaPrivateKey(privASN1));
    let pkcs8 = new Buffer(forge.util.bytesToHex(pkcs8Bytes), 'hex');

    nodeJose.JWK.asKey(pkcs8, 'pkcs8')
      .then(jwk => {
        let client = new MockClient(jwk);

        let notThumbprint = 'not-thumbprint';
        let cert = {
          id:          notThumbprint,
          thumbprint:  notThumbprint,
          der:         certDER,
          type:        function() { return 'cert'; },
          marshal:     function() { return this.der; },
          contentType: function() { return 'application/pkix-cert'; }
        };
        acmeServer.db.put(cert);

        let revocationRequest = {
          certificate: jose.base64url.encode(certDER),
          reason:      reason
        };
        let url = acmeServer.baseURL + revokePath;
        let nonce = acmeServer.transport.nonces.get();
        return client.makeJWS(nonce, url, revocationRequest);
      })
      .then(jws => promisify(testServer.post(revokePath).send(jws)))
      .then(res => {
        assert.equal(res.status, 200);
        done();
      })
      .catch(done);
  });

  it('blocks revocation of an unknown cert', (done) => {
    let revokePath = '/revoke-cert';
    let revocationRequest = { certificate: 'unknown-cert' };
    let url = acmeServer.baseURL + revokePath;
    let nonce = acmeServer.transport.nonces.get();

    mockClient.makeJWS(nonce, url, revocationRequest)
      .then(jws => promisify(testServer.post(revokePath).send(jws)))
      .then(res => {
        assert.equal(res.status, 403);
        done();
      })
      .catch(done);
  });

  it('blocks revocation by an unknown key', (done) => {
    let certDER = cachedCrypto.certReq.cert;
    let reason = 3;
    let revokePath = '/revoke-cert';

    let notThumbprint = 'not-thumbprint';
    let cert = {
      id:          notThumbprint,
      thumbprint:  notThumbprint,
      der:         certDER,
      type:        function() { return 'cert'; },
      marshal:     function() { return this.der; },
      contentType: function() { return 'application/pkix-cert'; }
    };
    acmeServer.db.put(cert);

    let revocationRequest = {
      certificate: jose.base64url.encode(certDER),
      reason:      reason
    };
    let url = acmeServer.baseURL + revokePath;
    let nonce = acmeServer.transport.nonces.get();

    mockClient.makeJWS(nonce, url, revocationRequest)
      .then(jws => promisify(testServer.post(revokePath).send(jws)))
      .then(res => {
        assert.equal(res.status, 403);
        done();
      })
      .catch(done);
  });

  it('converts a non-integer reason code to zero', (done) => {
    let certDER = cachedCrypto.certReq.cert;
    let reason = 'no-reason';
    let certPath;
    let revokePath = '/revoke-cert';

    mockClient.key()
      .then(k => registerKey(k, acmeServer))
      .then(thumbprint => {
        let cert = {
          id:          thumbprint,
          regID:       thumbprint,
          der:         certDER,
          type:        function() { return 'cert'; },
          marshal:     function() { return this.der; },
          contentType: function() { return 'application/pkix-cert'; }
        };
        acmeServer.db.put(cert);

        certPath = `/cert/${cert.id}`;

        let revocationRequest = {
          certificate: jose.base64url.encode(certDER),
          reason:      reason
        };
        let url = acmeServer.baseURL + revokePath;
        let nonce = acmeServer.transport.nonces.get();
        return mockClient.makeJWS(nonce, url, revocationRequest);
      })
      .then(jws => promisify(testServer.post(revokePath).send(jws)))
      .then(res => {
        assert.equal(res.status, 200);
        return promisify(testServer.get(certPath));
      })
      .then(res => {
        assert.equal(res.status, 200);
        assert.property(res.headers, 'revocation-reason');
        assert.equal(parseInt(res.headers['revocation-reason']), 0);
        done();
      })
      .catch(done);
  });
});
