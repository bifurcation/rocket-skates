// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert        = require('chai').assert;
const request       = require('supertest');
const urlParse      = require('url').parse;
const https         = require('https');
const MockClient    = require('./tools/mock-client');
const AutoChallenge = require('./tools/auto-challenge');
const promisify     = require('./tools/promisify');
const cachedCrypto  = require('./tools/cached-crypto');
const jose          = require('../lib/jose');
const pki           = require('../lib/pki');
const ACMEServer    = require('../lib/server/acme-server');

let localCA = new pki.CA();
let mockClient = new MockClient();

const serverConfig = {
  host:               '127.0.0.1',
  port:               443, // NB: This is a lie
  authzExpirySeconds: 30 * 24 * 3600,
  challengeTypes:     [AutoChallenge],
  CA:                 localCA
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
        id:      thumbprint,
        key:     mockClient._key,
        contact: ['mailto:anonymous@example.com'],
        type:    function() { return 'reg'; },
        marshal: function() {
          return {
            key:       this.key.toJSON(),
            status:    this.status,
            contact:   this.contact,
            agreement: this.agreement
          };
        }
      };
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
          id:   jose.base64url.encode(tpBuffer),
          type: function() { return 'reg'; }
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

        let authz = res.body.requirements.map(req => {
          if (req.type !== 'authorization') {
            return Promise.resolve(false);
          }
          let authzPath = path(req.url);
          return promisify(testServer.get(authzPath));
        });
        return Promise.all(authz);
      })
      .then(responses => {
        let challengeTests = [];
        let authzNames = [];
        responses.map(res => {
          if (res == null) {
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
              .then(challRes => assert.equal(challRes.status, 200))
              .then(() => promisify(testServer.get(authzPath)))
              .then(authzRes => {
                assert.equal(authzRes.status, 200);
                assert.equal(authzRes.body.status, 'valid');
              });
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
      id:         'not-your-thumbprint',
      thumbprint: 'not-your-thumbprint',
      type:       function() { return 'app'; },
      touched:    false,

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
      .then(k => k.thumbprint())
      .then(tpBuffer => {
        let thumbprint = jose.base64url.encode(tpBuffer);
        let existing = {
          id:         thumbprint,
          thumbprint: thumbprint,
          challenges: [null],
          type:       function() { return 'authz'; }
        };
        acmeServer.db.put(existing);

        challPath = `authz/${thumbprint}/0`;

        let nonce = acmeServer.transport.nonces.get();
        let url = `${acmeServer.baseURL}/${challPath}`;
        return mockClient.makeJWS(nonce, url, {});
      })
      .then(jws => promisify(testServer.post(`/${challPath}`).send(jws)))
      .then(res => {
        assert.equal(res.status, 401);
        done();
      })
      .catch(done);
  });

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
          thumbprint:  thumbprint,
          der:         certDER,
          type:        function() { return 'cert'; },
          marshal:     function() { return this.der; },
          contentType: function() { return 'application/pkix-cert'; }
        };
        acmeServer.db.put(cert);

        certPath = `/cert/${thumbprint}`;

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
        done();
      })
      .catch(done);
  });

  it('revokes a certificate when authorized by another account key', () => {
    // Provision reg
    // Provision authz
    // Provision cert
  });

  it('revokes a certificate when authorized by the certificate key', () => {
    // Provision cert
  });
});
