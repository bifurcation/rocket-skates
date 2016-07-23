// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert     = require('chai').assert;
const nock       = require('nock');
const jose       = require('../lib/jose');
const ACMEClient = require('../lib/acme-client');


describe('ACME client', () => {
  let directoryURL = 'http://example.com/directory';
  let directory = {
    'meta': {
      'terms-of-service': 'http://example.com/terms'
    },
    'new-reg': 'http://example.com/new-reg',
    'new-app': 'http://example.com/new-app'
  };
  let server = nock('http://example.com');

  afterEach(() => {
    nock.cleanAll();
  });

  it('fails if no account key is provided', () => {
    try {
      new ACMEClient({directoryURL: 'not-null'});
      assert.ok(false);
    } catch (e) {
      assert.ok(true);
    }
  });

  it('fails if no directory URL is provided', () => {
    try {
      new ACMEClient();
      assert.ok(false);
    } catch (e) {
      assert.ok(true);
    }
  });

  it('fetches and caches the directory', (done) => {
    let client;

    server.get('/directory').reply(200, directory);

    jose.newkey()
      .then(key => {
        client = new ACMEClient({
          accountKey:   key,
          directoryURL: directoryURL
        });
        return client.directory();
      })
      .then(received => {
        assert.isTrue(server.isDone());
        assert.deepEqual(received, directory);
        return client.directory();
      })
      .then(received => {
        assert.deepEqual(received, directory);
        done();
      })
      .catch(done);
  });

  it('performs a registration', (done) => {
    let contact = ['mailto:anonymous@example.com'];
    let regResponse = {contact: contact};
    let regHeaders = {location: 'http://example.com/reg/asdf'};

    let gotNewReg = false;
    server.get('/directory').reply(200, directory)
          .head('/new-reg').reply(200, '', {'replay-nonce': 'foo'})
          .post('/new-reg')
          .reply((uri, jws, cb) => {
            gotNewReg = true;
            return jose.verify(jws)
              .then(verified => {
                assert.deepEqual(verified.payload, {contact: contact});
                cb(null, [200, regResponse, regHeaders]);
              })
              .catch(e => {
                cb(null, [501, e.message]);
              });
          });

    jose.newkey()
      .then(key => {
        regResponse.key = key.toJSON();
        let client = new ACMEClient({
          accountKey:   key,
          directoryURL: directoryURL
        });
        return client.register(contact);
      })
      .then(() => {
        assert.isTrue(gotNewReg);
        done();
      })
      .catch(done);
  });

  it('agrees to terms', (done) => {
    let termsURL = 'http://example.com/terms';
    let contact = ['mailto:anonymous@example.com'];
    let regResponse = {contact: contact};
    let regHeaders = {
      location:       'http://example.com/reg/asdf',
      link:           '<http://example.com/terms>; rel="terms-of-service"',
      'replay-nonce': 'foo'
    };

    let gotNewReg = false;
    let gotAgreement = false;
    server.get('/directory').reply(200, directory)
          .head('/new-reg').reply(200, '', {'replay-nonce': 'foo'})
          .post('/new-reg')
          .reply((uri, jws, cb) => {
            gotNewReg = true;
            return jose.verify(jws)
              .then(verified => {
                assert.deepEqual(verified.payload, {contact: contact});
                cb(null, [200, regResponse, regHeaders]);
              })
              .catch(e => {
                cb(null, [501, e.message]);
              });
          })
          .post('/reg/asdf')
          .reply((uri, jws, cb) => {
            gotAgreement = true;
            return jose.verify(jws)
              .then(verified => {
                assert.propertyVal(verified.payload, 'agreement', termsURL);
                regResponse.agreement = verified.payload.agreement;
                cb(null, [200, regResponse, regHeaders]);
              })
              .catch(e => {
                cb(null, [501, e.message]);
              });
          });

    jose.newkey()
      .then(key => {
        regResponse.key = key.toJSON();
        let client = new ACMEClient({
          accountKey:   key,
          directoryURL: directoryURL
        });
        client.agreementCallback = (() => true);
        return client.register(contact);
      })
      .then(() => {
        assert.isTrue(gotNewReg);
        assert.isTrue(gotAgreement);
        done();
      })
      .catch(done);
  });

  // XXX(#29): Test registration failure cases
  it('fails if there is no new-reg endpoint', () => {});
  it('fails if there is no location', () => {});
  it('fails if there is no key', () => {});
  it('fails if there is an incorrect key', () => {});
  it('fails if the user declines terms', () => {});

  it('requests a certificate', (done) => {
    let csr = 'todo';
    let notBefore = new Date();
    let notAfter = new Date();
    notAfter.setTime(notBefore.getTime() + 7 * 24 * 3600);

    let stub = {
      csr:       csr,
      notBefore: notBefore.toJSON(),
      notAfter:  notAfter.toJSON()
    };
    let app = {
      csr:       csr,
      notBefore: notBefore,
      notAfter:  notAfter,

      status:  'pending',
      expires: notAfter,

      requirements: [{
        type:   'authorization',
        status: 'pending',
        url:    'http://example.com/authz/asdf'
      }]
    };
    let newAppHeaders = {
      location:       'http://example.com/app/asdf',
      'replay-nonce': 'foo'
    };
    // TODO make this constructed from a tool
    let autoChallenge = {
      type:  'auto',
      url:   'http://example.com/authz/asdf/0',
      token: '12345'
    };
    let authz = {
      identifier: {
        type:  'dns',
        value: 'not-example.com'
      },
      status:     'pending',
      challenges: [autoChallenge]
    };
    let completed = {};
    Object.assign(completed, app);
    completed.status = 'valid';
    completed.certificate = 'http://example.com/cert/asdf';

    let gotNewApp = false;
    let gotAuthzFetch = false;
    server.get('/directory').reply(200, directory)
          .head('/new-app').reply(200, '', {'replay-nonce': 'foo'})
          .post('/new-app')
          .reply((uri, jws, cb) => {
            gotNewApp = true;
            return jose.verify(jws)
              .then(verified => {
                assert.deepEqual(verified.payload, stub);
                cb(null, [201, app, newAppHeaders]);
              })
              .catch(e => {
                cb(null, [501, e.message]);
              });
          })
          .get('/authz/asdf').reply((uri, jws, cb) => {
            gotAuthzFetch = true;
            cb(null, [201, authz]);
          })
          .post('/authz/asdf/0')
          .reply((uri, jws, cb) => {
            // TODO gotChallengePost = true;
            return jose.verify(jws)
              .then(() => {
                cb(null, [200, autoChallenge]);
              })
              .catch(e => {
                cb(null, [501, e.message]);
              });
          })
          .get('/app/asdf').reply(200, app)
          .get('/app/asdf').reply(200, app)
          .get('/app/asdf').reply(200, completed)
          .get('/cert/asdf').reply(200, completed)
          .get('/cert/asdf').reply(200, completed);

    jose.newkey()
      .then(key => {
        let client = new ACMEClient({
          accountKey:   key,
          directoryURL: directoryURL
        });

        client.registrationURL = 'non-null';
        return client.requestCertificate(csr, notBefore, notAfter);
      })
      .then(() => {
        assert.isTrue(gotNewApp);
        assert.isTrue(gotAuthzFetch);
        done();
      })
      .catch(done);
  });

  it('fetches an auto-issued certificate', () => {});
  it('fails if unregistered', () => {});
  it('fails if there is no new-app endpoint', () => {});
  it('fails if there is no location (new-app)', () => {});
  it('fails if no certificate is provided for a valid application', () => {});


  /*
  it('performs a registration', (done) => {
    let content = {'result': true};
    let headers = {
      'location': 'https://example.com/asdf',
      'link':     '<https://example.com/terms>; rel="terms-of-service"'
    };
    nock('http://example.com')
      .get('/foo').reply(200, content, headers);

    TransportClient.get('http://example.com/foo')
      .then(body => {
        assert.deepEqual(body, content);
        done();
      })
      .catch(done);
  });

  it('performs a binary GET request', (done) => {
    let content = 'asdf';
    nock('http://example.com')
      .get('/foo').reply(200, content);

    TransportClient.get('http://example.com/foo', true)
      .then(body => {
        assert.isTrue(body instanceof Buffer);
        assert.equal(body.toString(), content);
        done();
      })
      .catch(done);
  });

  it('polls until completion or timeout', (done) => {
    let test = (body => body.foo);
    nock('http://example.com')
      .get('/foo').reply(200, {})
      .get('/foo').reply(200, {'foo': 'bar'});

    TransportClient.poll('http://example.com/foo', test)
      .then(body => {
        assert.ok(test(body));
      })
      .catch(err => assert.ok(false, err.message))
      .then(() => {
        nock('http://example.com')
          .get('/foo').reply(200, {})
          .get('/foo').reply(200, {})
          .get('/foo').reply(200, {'foo': 'bar'});
        return TransportClient.poll('http://example.com/foo', test, 2, 10);
      })
      .then(() => { done(new Error('should have failed')); })
      .catch(() => { done(); });
  });

  it('sends a POST with no preflight', (done) => {
    let gotHEAD = false;
    let gotPOST = false;
    let nonce = 'foo';
    nock('http://example.com')
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
            cb(null, [200, '']);
          })
          .catch(err => {
            cb(null, [400, err.message]);
          });
      });

    jose.newkey()
      .then(k => {
        let client = new TransportClient({accountKey: k});
        client.nonces.push(nonce);
        return client.post('http://example.com/foo', {'foo': 'bar'});
      })
      .then(() => {
        assert.isFalse(gotHEAD);
        assert.isTrue(gotPOST);
        done();
      })
      .catch(done);
  });

  it('sends a POST with preflight', (done) => {
    let gotHEAD = false;
    let gotPOST = false;
    let nonce = 'foo';
    nock('http://example.com')
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

    jose.newkey()
      .then(k => {
        let client = new TransportClient({accountKey: k});
        return client.post('http://example.com/foo', {'foo': 'bar'});
      })
      .then(() => {
        assert.isTrue(gotHEAD);
        assert.isTrue(gotPOST);
        done();
      })
      .catch(done);
  });

  it('fails POST if preflight fails', (done) => {
    nock('http://example.com')
      .head('/foo').reply(200);

    jose.newkey()
      .then(k => {
        let client = new TransportClient({accountKey: k});
        return client.post('http://example.com/foo', {'foo': 'bar'});
      })
      .then(() => { done(new Error('should have failed')); })
      .catch(() => { done(); });
  });
  */
});
