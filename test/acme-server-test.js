// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert        = require('chai').assert;
const request       = require('supertest');
const urlParse      = require('url');
const MockClient    = require('./tools/mock-client');
const promisify     = require('./tools/promisify');
const AutoChallenge = require('./tools/auto-challenge');
const ACMEServer    = require('../lib/acme-server');

let serverConfig = {
  host:               '127.0.0.1',
  authzExpirySeconds: 30 * 24 * 3600,
  challengeTypes:     [AutoChallenge]
};
let mockClient = new MockClient();

// CSR generated by a Go script
// * Random public key
// * Two SANs:
//  * not-example.com
//  * www.not-example.com
let testCSR = 'MIICoTCCAYkCAQAwGjEYMBYGA1UEAxMPbm90LWV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq7F00dtBUeN9DHEiDRimh5OtlU0KDXw-B-04kBaZkTtXU-1G3GW-BG9p_M0PyT7NSn5rYcdzisajTQZJD-cQgltgevWARc8dkrIy4ogj4qihwagO-glAo20ZZoreibdL3cpOM2kmjRkkXDCFDXZF1kL8LhoKRg1H5dmkVcgw7ALr-AhRUHcvVmkv4XwGT_H1fzgutTCIMvEwnKIsn1lw6q5rK6pUktnsGQqJFrzJ_RUN_CK0BPg3BD9QOkwxXZ9ZTMttAIrZMuBA3wf_83_erI53s_46PMgLI3rDpPa9clqylSZGEDwXy8sLwQXSSuWCMLD_t99MZvDFcDjPSyJUaQIDAQABoEIwQAYJKoZIhvcNAQkOMTMwMTAvBgNVHREEKDAmgg9ub3QtZXhhbXBsZS5jb22CE3d3dy5ub3QtZXhhbXBsZS5jb20wDQYJKoZIhvcNAQEFBQADggEBAFoGL91KCrF1UaT-ZHOoC_SfXA9O2zsLHZDAqfcciqPn85pCUDntdbxiSAmfMt_K6PI-MqlWIR2ejZG7yYpT1Nx3UyDggRQiAS8WRPw8M9B43Ang5HnaOX2Y7q0J0TTGQXBO3Ts8advtQcvaOJMvpAborebQizzN0pzhMkBcAOgzZQVKWJvwqMzQsD5VJP8gw7i-HH3IROep3Ayu74gTDYvfVyMJEIbY1D4P3FcoUcc-K0mOYlIu1a8zS6KDCRj5rrhR1dmMj8bd_V6e9234lXHaZFTKDPcVowT8w9LwB4DJPzQu7b7grtynFV645q_-aSxPxJGmj7i-aayO-T00cUE';
let testCSRNames = ['not-example.com', 'www.not-example.com'];

function path(url) {
  return urlParse.parse(url).path;
}

describe('ACME server', () => {
  it('responds to a directory request', (done) => {
    let server = new ACMEServer(serverConfig);
    let termsURL = 'https://example.com/terms';

    server.terms = termsURL;

    promisify(request(server.app).get('/directory'))
      .then(res => {
        assert.equal(res.status, 200);

        assert.property(res.headers, 'content-type');
        assert.include(res.headers['content-type'], 'application/json');

        assert.property(res.body, 'meta');
        assert.isObject(res.body.meta);
        assert.property(res.body.meta, 'terms-of-service');
        assert.equal(res.body.meta['terms-of-service'], termsURL);

        assert.property(res.body, 'new-reg');
        assert.property(res.body, 'new-app');
        // TODO Add things here as they get added to the directory
        done();
      })
      .catch(done);
  });

  it('answers a valid fetch', (done) => {
    let server = new ACMEServer(serverConfig);
    let reg = {
      type:        function() { return 'foo'; },
      id:          'bar',
      marshal:     function() { return {baz: 42}; },
      contentType: function() { return 'application/json'; }
    };

    server.db.put(reg);
    promisify(request(server.app).get('/foo/bar'))
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
    let server = new ACMEServer(serverConfig);
    request(server.app)
      .get('/reg/foo')
      .expect(401, done);
  });

  it('rejects a fetch for a non-existent object', (done) => {
    let server = new ACMEServer(serverConfig);
    request(server.app)
      .get('/foo/bar')
      .expect(404, done);
  });

  it('creates a new registration', (done) => {
    let server = new ACMEServer(serverConfig);
    let termsURL = 'https://example.com/terms';
    server.terms = termsURL;

    let nonce = server.transport.nonces.get();
    let url = server.baseURL + 'new-reg';
    let reg = {contact: ['mailto:anonymous@example.com']};
    let regPath;
    let created;

    let testServer = request(server.app);
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

  it('rejects a new registration for an existing key', (done) => {
    let server = new ACMEServer(serverConfig);
    let termsURL = 'https://example.com/terms';
    server.terms = termsURL;

    let nonce = server.transport.nonces.get();
    let url = server.baseURL + 'new-reg';
    let reg = {contact: ['mailto:anonymous@example.com']};
    let jws;

    mockClient.makeJWS(nonce, url, reg)
      .then(signed => {
        jws = signed;
        return mockClient._key.thumbprint();
      })
      .then(tpBuffer => {
        let existing = {
          id:   tpBuffer.toString('hex'),
          type: function() { return 'reg'; }
        };
        server.db.put(existing);

        request(server.app)
          .post('/new-reg')
          .send(jws)
          .expect(409)
          .expect('location', /.*/, done);
      });
  });

  it('updates a registration', (done) => {
    let server = new ACMEServer(serverConfig);
    let termsURL = 'https://example.com/terms';
    server.terms = termsURL;

    let nonce = server.transport.nonces.get();
    let thumbprint;

    let reg2 = {
      contact:   ['mailto:someone@example.org'],
      agreement: termsURL
    };

    mockClient.key()
      .then(k => k.thumbprint())
      .then(tpBuffer => {
        thumbprint = tpBuffer.toString('hex');
        let url = `${server.baseURL}reg/${thumbprint}`;
        return mockClient.makeJWS(nonce, url, reg2);
      })
      .then(jws => {
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

        return promisify(request(server.app).post(`/reg/${existing.id}`).send(jws));
      })
      .then(res => {
        assert.equal(res.status, 200);

        assert.property(res.body, 'key');
        assert.property(res.body, 'contact');
        assert.property(res.body, 'agreement');

        assert.deepEqual(res.body.key, mockClient._key.toJSON());
        assert.deepEqual(res.body.contact, reg2.contact);
        assert.deepEqual(res.body.agreement, reg2.agreement);
        done();
      });
  });

  it('creates a new application', (done) => {
    let server = new ACMEServer(serverConfig);

    let thumbprint;
    let nonce = server.transport.nonces.get();
    let url = server.baseURL + 'new-app';
    let app = {
      'csr':       testCSR,
      'notBefore': '2016-07-14T23:19:36.197Z',
      'notAfter':  '2017-07-14T23:19:36.197Z'
    };

    let testServer = request(server.app);
    mockClient.key()
      .then(k => k.thumbprint())
      .then(tpBuffer => {
        thumbprint = tpBuffer.toString('hex');
        return mockClient.makeJWS(nonce, url, app);
      })
      .then(jws => {
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

        return promisify(testServer.post('/new-app').send(jws));
      })
      .then(res => {
        assert.equal(res.status, 201);

        assert.property(res.headers, 'location');

        assert.property(res.body, 'status');
        assert.property(res.body, 'csr');
        assert.property(res.body, 'notBefore');
        assert.property(res.body, 'notAfter');
        assert.property(res.body, 'requirements');

        assert.equal(res.body.csr, app.csr);
        assert.equal(res.body.notBefore, app.notBefore);
        assert.equal(res.body.notAfter, app.notAfter);
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

        assert.deepEqual(authzNames.sort(), testCSRNames.sort());
        return Promise.all(challengeTests);
      })
      .then(() => { done(); })
      .catch(done);
  });

  it('rejects a new application from an unregistered key', () => {});
  it('rejects a new application with an invalid csr', () => {});
  it('rejects a new application with an invalid notBefore', () => {});
  it('rejects a new application with an invalid notAfter', () => {});

  it('issues a certificate', function(done) {
    this.timeout(10000);

    let server = new ACMEServer(serverConfig);

    let nonce = server.transport.nonces.get();
    let url = server.baseURL + 'new-app';
    let app = {
      'csr':       testCSR,
      'notBefore': '2016-07-14T23:19:36.197Z',
      'notAfter':  '2017-07-14T23:19:36.197Z'
    };

    let thumbprint;
    let appPath;
    let testServer = request(server.app);
    mockClient.key()
      .then(k => k.thumbprint())
      .then(tpBuffer => {
        thumbprint = tpBuffer.toString('hex');
        return mockClient.makeJWS(nonce, url, app);
      })
      .then(jws => {
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

        return promisify(testServer.post('/new-app').send(jws));
      })
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
                let challNonce = server.transport.nonces.get();
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
        // TODO: Test that the returned value is a valid certificate

        done();
      })
      .catch(done);
  });
});
