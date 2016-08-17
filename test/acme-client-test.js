// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert         = require('chai').assert;
const nock           = require('nock');
const jose           = require('../lib/jose');
const cachedCrypto   = require('./tools/cached-crypto');
const AutoValidation = require('./tools/auto-validation');
const ACMEClient     = require('../lib/client/acme-client');


describe('ACME client', () => {
  let accountKey;
  let directoryURL = 'https://example.com/directory';
  let directory = {
    'meta': {
      'terms-of-service': 'https://example.com/terms'
    },
    'new-reg':     'https://example.com/new-reg',
    'new-app':     'https://example.com/new-app',
    'revoke-cert': 'https://example.com/revoke-cert'
  };
  let server = nock('https://example.com');

  before((done) => {
    cachedCrypto.key
      .then(k => { accountKey = k; done(); })
      .catch(done);
  });

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

  it('fails if a bad validation type is provided', () => {
    class NotAValidation {}

    try {
      new ACMEClient({
        accountKey:      accountKey,
        directoryURL:    directoryURL,
        validationTypes: [NotAValidation]
      });
      assert.ok(false);
    } catch (e) {
      assert.ok(true);
    }
  });

  it('fetches and caches the directory', (done) => {
    let client = new ACMEClient({
      accountKey:   accountKey,
      directoryURL: directoryURL
    });

    server.get('/directory').reply(200, directory);

    client.directory()
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
    let regResponse = {
      key:     accountKey.toJSON(),
      contact: contact
    };
    let regHeaders = {location: 'https://example.com/reg/asdf'};

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

    let client = new ACMEClient({
      accountKey:   accountKey,
      directoryURL: directoryURL
    });
    client.register(contact)
      .then(() => {
        assert.isTrue(gotNewReg);
        done();
      })
      .catch(done);
  });

  it('agrees to terms', (done) => {
    let termsURL = 'https://example.com/terms';
    let contact = ['mailto:anonymous@example.com'];
    let regResponse = {
      key:     accountKey.toJSON(),
      contact: contact
    };
    let regHeaders = {
      location:       'https://example.com/reg/asdf',
      link:           '<https://example.com/terms>; rel="terms-of-service"',
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

    let client = new ACMEClient({
      accountKey:        accountKey,
      directoryURL:      directoryURL,
      agreementCallback: (() => true)
    });
    client.register(contact)
      .then(() => {
        assert.isTrue(gotNewReg);
        assert.isTrue(gotAgreement);
        done();
      })
      .catch(done);
  });

  function testNewRegFail(done, msg, agreementCallback) {
    let client = new ACMEClient({
      accountKey:        accountKey,
      directoryURL:      directoryURL,
      agreementCallback: agreementCallback || (() => true)
    });
    client.register(['mailto:someone@example.com'])
      .then(() => { done(new Error('register succeeded when it should not have')); })
      .catch(err => {
        if (msg) {
          assert.equal(err.message, msg);
        }
        done();
      })
      .catch(done);
  }

  it('fails if there is no new-reg endpoint', (done) => {
    server.get('/directory').reply(200, {});
    return testNewRegFail(done, 'Server does not have a new-registration endpoint');
  });

  it('fails if there is no location in new-reg response', (done) => {
    server.get('/directory').reply(200, directory)
          .head('/new-reg').reply(200, '', {'replay-nonce': 'foo'})
          .post('/new-reg')
          .reply(201, {}, {});
    return testNewRegFail(done, 'No Location header in new-registration response');
  });

  it('fails if there is no key', (done) => {
    let regHeaders = {'location': 'foo'};
    let regResponse = {};
    server.get('/directory').reply(200, directory)
          .head('/new-reg').reply(200, '', {'replay-nonce': 'foo'})
          .post('/new-reg')
          .reply(201, regResponse, regHeaders);
    return testNewRegFail(done, '"key" field omitted from registration object');
  });

  it('fails if there is an incorrect key', (done) => {
    let regHeaders = {location: 'foo'};
    let regResponse = {key: 'incorrect'};
    server.get('/directory').reply(200, directory)
          .head('/new-reg').reply(200, '', {'replay-nonce': 'foo'})
          .post('/new-reg')
          .reply(201, regResponse, regHeaders);
    return testNewRegFail(done, 'Incorrect key in registration');
  });

  it('fails if there is an incorrect contact', (done) => {
    let regHeaders = {location: 'foo'};
    server.get('/directory').reply(200, directory)
          .head('/new-reg').reply(200, '', {'replay-nonce': 'foo'})
          .post('/new-reg')
          .reply((uri, jws, cb) => {
            return jose.verify(jws)
              .then(verified => {
                let regResponse = {
                  key:     verified.key.toJSON(),
                  contact: []
                };
                cb(null, [201, regResponse, regHeaders]);
              })
              .catch(e => {
                cb(null, [501, e.message]);
              });
          });
    return testNewRegFail(done, 'Incorrect contact in registration');
  });

  it('fails if there is an incorrect agreement', (done) => {
    let regResponse = {contact: ['mailto:someone@example.com']};
    let regHeaders = {
      location:       'https://example.com/reg/asdf',
      link:           '<https://example.com/terms>; rel="terms-of-service"',
      'replay-nonce': 'foo'
    };
    server.get('/directory').reply(200, directory)
          .head('/new-reg').reply(200, '', {'replay-nonce': 'foo'})
          .post('/new-reg')
          .reply((uri, jws, cb) => {
            return jose.verify(jws)
              .then(verified => {
                regResponse.key = verified.key.toJSON();
                cb(null, [201, regResponse, regHeaders]);
              });
          })
          .post('/reg/asdf')
          .reply((uri, jws, cb) => {
            return jose.verify(jws)
              .then(verified => {
                regResponse.key = verified.key.toJSON();
                regResponse.agreement = 'invalid';
                cb(null, [200, regResponse, regHeaders]);
              });
          });
    return testNewRegFail(done, 'Incorrect agreement in registration');
  });

  it('fails if the user declines terms', (done) => {
    let regResponse = {contact: ['mailto:someone@example.com']};
    let regHeaders = {
      location:       'https://example.com/reg/asdf',
      link:           '<https://example.com/terms>; rel="terms-of-service"',
      'replay-nonce': 'foo'
    };
    server.get('/directory').reply(200, directory)
          .head('/new-reg').reply(200, '', {'replay-nonce': 'foo'})
          .post('/new-reg')
          .reply((uri, jws, cb) => {
            return jose.verify(jws)
              .then(verified => {
                regResponse.key = verified.key.toJSON();
                cb(null, [201, regResponse, regHeaders]);
              });
          });
    return testNewRegFail(done, 'User did not agree to terms', () => false);
  });

  it('requests a certificate', (done) => {
    let stub = {
      csr:       cachedCrypto.certReq.csr,
      notBefore: cachedCrypto.certReq.notBefore.toJSON(),
      notAfter:  cachedCrypto.certReq.notAfter.toJSON()
    };
    let app = {
      csr:       cachedCrypto.certReq.csr,
      notBefore: cachedCrypto.certReq.notBefore.toJSON(),
      notAfter:  cachedCrypto.certReq.notAfter.toJSON(),

      status:  'pending',
      expires: cachedCrypto.certReq.notAfter.toJSON(),

      requirements: [{
        type:   'authorization',
        status: 'pending',
        url:    'https://example.com/authz/asdf'
      }]
    };
    let newAppHeaders = {
      location:       'https://example.com/app/asdf',
      'replay-nonce': 'foo'
    };
    let autoChallenge = {
      type:  'auto',
      url:   'https://example.com/authz/asdf/0',
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
    completed.certificate = 'https://example.com/cert/asdf';

    let gotNewApp = false;
    let gotAuthzFetch = false;
    let gotChallengePOST = false;
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
            gotChallengePOST = true;
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
          .get('/cert/asdf').reply(200, cachedCrypto.certReq.cert);

    let client = new ACMEClient({
      accountKey:      accountKey,
      directoryURL:    directoryURL,
      validationTypes: [AutoValidation]
    });
    client.registrationURL = 'non-null';
    client.requestCertificate(cachedCrypto.certReq.csr,
                              cachedCrypto.certReq.notBefore,
                              cachedCrypto.certReq.notAfter)
      .then(cert => {
        assert.isTrue(gotNewApp);
        assert.isTrue(gotAuthzFetch);
        assert.isTrue(gotChallengePOST);
        assert.isTrue(cachedCrypto.certReq.cert.equals(cert));
        done();
      })
      .catch(done);
  });

  it('fetches a pre-issued certificate', (done) => {
    let app = {
      csr:       cachedCrypto.certReq.csr,
      notBefore: cachedCrypto.certReq.notBefore.toJSON(),
      notAfter:  cachedCrypto.certReq.notAfter.toJSON(),

      status:  'pending',
      expires: cachedCrypto.certReq.notAfter.toJSON(),

      requirements: [{
        type:   'authorization',
        status: 'valid',
        url:    'https://example.com/authz/asdf'
      }],

      certificate: 'https://example.com/cert/asdf'
    };
    let newAppHeaders = {
      location:       'https://example.com/app/asdf',
      'replay-nonce': 'foo'
    };

    let gotNewApp = false;
    let gotCertFetch = false;
    server.get('/directory').reply(200, directory)
          .head('/new-app').reply(200, '', {'replay-nonce': 'foo'})
          .post('/new-app')
          .reply((uri, jws, cb) => {
            gotNewApp = true;
            cb(null, [201, app, newAppHeaders]);
          })
          .get('/cert/asdf')
          .reply((uri, jws, cb) => {
            gotCertFetch = true;
            cb(null, [200, cachedCrypto.certReq.cert]);
          });

    let client = new ACMEClient({
      accountKey:      accountKey,
      directoryURL:    directoryURL,
      validationTypes: [AutoValidation]
    });
    client.registrationURL = 'non-null';
    client.requestCertificate(
        cachedCrypto.certReq.csr,
        cachedCrypto.certReq.notBefore,
        cachedCrypto.certReq.notAfter)
      .then(() => {
        assert.isTrue(gotNewApp);
        assert.isTrue(gotCertFetch);
        done();
      })
      .catch(done);
  });

  it('fails if unregistered', (done) => {
    let client = new ACMEClient({
      accountKey:      accountKey,
      directoryURL:    directoryURL,
      validationTypes: [AutoValidation]
    });
    client.requestCertificate(
        cachedCrypto.certReq.csr,
        cachedCrypto.certReq.notBefore,
        cachedCrypto.certReq.notAfter)
      .then(() => { done(new Error('new-app succeeded when it should not have')); })
      .catch(err => {
        assert.equal(err.message, 'Cannot request a certificate without registering');
        done();
      })
      .catch(done);
  });

  function testNewAppFail(done, msg) {
    let client = new ACMEClient({
      accountKey:   accountKey,
      directoryURL: directoryURL
    });
    client.registrationURL = 'non-null';
    client.requestCertificate(
        cachedCrypto.certReq.csr,
        cachedCrypto.certReq.notBefore,
        cachedCrypto.certReq.notAfter)
      .then(() => { done(new Error('New-app succeeded when it should not have')); })
      .catch(err => {
        if (msg) {
          assert.equal(err.message, msg);
        }
        done();
      })
      .catch(done);
  }

  it('fails if there is no new-app endpoint', (done) => {
    server.get('/directory').reply(200, {});
    return testNewAppFail(done, 'Server does not have a new-application endpoint');
  });

  it('fails if there is no location in new-app response', (done) => {
    server.get('/directory').reply(200, directory)
          .head('/new-app').reply(200, '', {'replay-nonce': 'foo'})
          .post('/new-app')
          .reply(201, {}, {});
    return testNewAppFail(done, 'No Location header in new-application response');
  });

  function testInvalidApp(done, app, msg) {
    let newAppHeaders = {
      location: 'https://example.com/app/asdf'
    };

    server.get('/directory').reply(200, directory)
          .head('/new-app').reply(200, '', {'replay-nonce': 'foo'})
          .post('/new-app')
          .reply(201, app, newAppHeaders);
    return testNewAppFail(done, msg);
  }

  it('fails if the application is incomplete', (done) => {
    testInvalidApp(done, {
      status:       'pending',
      requirements: []
    }, 'Application is missing a required field');
  });

  it('fails if the application has the wrong CSR', (done) => {
    testInvalidApp(done, {
      csr:          cachedCrypto.certReq.csr + '-not',
      status:       'pending',
      requirements: []
    }, 'Incorrect CSR in application');
  });

  it('fails if the application has the wrong notBefore', (done) => {
    testInvalidApp(done, {
      csr:          cachedCrypto.certReq.csr,
      status:       'pending',
      requirements: []
    }, 'Incorrect notBefore in application');
  });

  it('fails if the application has the wrong notAfter', (done) => {
    testInvalidApp(done, {
      csr:          cachedCrypto.certReq.csr,
      notBefore:    cachedCrypto.certReq.notBefore.toJSON(),
      status:       'pending',
      requirements: []
    }, 'Incorrect notAfter in application');
  });

  it('fails if the application has no requirements', (done) => {
    testInvalidApp(done, {
      csr:          cachedCrypto.certReq.csr,
      notBefore:    cachedCrypto.certReq.notBefore.toJSON(),
      notAfter:     cachedCrypto.certReq.notAfter.toJSON(),
      status:       'pending',
      requirements: []
    }, 'No requirements in application');
  });

  it('fails if the application has an unsupported requirement', (done) => {
    testInvalidApp(done, {
      csr:          cachedCrypto.certReq.csr,
      notBefore:    cachedCrypto.certReq.notBefore.toJSON(),
      notAfter:     cachedCrypto.certReq.notAfter.toJSON(),
      status:       'pending',
      requirements: [{type: 'unsupported'}]
    }, 'Unsupported requirement type: unsupported');
  });

  function testInvalidAuthz(done, authz, msg) {
    let app = {
      csr:          cachedCrypto.certReq.csr,
      notBefore:    cachedCrypto.certReq.notBefore.toJSON(),
      notAfter:     cachedCrypto.certReq.notAfter.toJSON(),
      status:       'pending',
      requirements: [{
        type:   'authorization',
        status: 'pending',
        url:    'https://example.com/authz/asdf'
      }]
    };
    let newAppHeaders = {
      location: 'https://example.com/app/asdf'
    };

    server.get('/directory').reply(200, directory)
          .head('/new-app').reply(200, '', {'replay-nonce': 'foo'})
          .post('/new-app').reply(201, app, newAppHeaders)
          .get('/authz/asdf').reply(200, authz);
    return testNewAppFail(done, msg);
  }

  it('fails if the authorization is missing a required field', (done) => {
    testInvalidAuthz(done, {}, 'Authorization is missing a required field');
  });

  it('fails if the authz identifier is malformed', (done) => {
    testInvalidAuthz(done, {
      identifier: 'nonsense',
      status:     'pending',
      challenges: []
    }, 'Authorization identifier is malformed');
  });

  it('fails if the authz has no challenges', (done) => {
    testInvalidAuthz(done, {
      identifier: {type: 'dns', value: 'example.com'},
      status:     'pending',
      challenges: []
    }, 'No challenges provided in application');
  });

  it('fails if the authz has an invalid challenge', (done) => {
    testInvalidAuthz(done, {
      identifier: {type: 'dns', value: 'example.com'},
      status:     'pending',
      challenges: [{}]
    }, 'Missing field in challenge');
  });

  it('fails if the authz has an invalid combinations field', (done) => {
    testInvalidAuthz(done, {
      identifier: {type: 'dns', value: 'example.com'},
      status:     'pending',
      challenges: [{
        type: 'auto',
        url:  'non-empty'
      }],
      combinations: 'nonsense'
    }, 'Malformed combinations field in application');
  });

  it('fails if the authz has an invalid combinations value', (done) => {
    testInvalidAuthz(done, {
      identifier: {type: 'dns', value: 'example.com'},
      status:     'pending',
      challenges: [{
        type: 'auto',
        url:  'non-empty'
      }],
      combinations: [0]
    }, 'Malformed combination value in application');
  });

  it('fails if the authz has an invalid combination', (done) => {
    testInvalidAuthz(done, {
      identifier: {type: 'dns', value: 'example.com'},
      status:     'pending',
      challenges: [{
        type: 'auto',
        url:  'non-empty'
      }],
      combinations: [[0, 2]]
    }, 'Combination value out of bounds');
  });

  it('fails if the authz has no supported combinations', (done) => {
    testInvalidAuthz(done, {
      identifier: {type: 'dns', value: 'example.com'},
      status:     'pending',
      challenges: [
        {type: 'auto', url: 'non-empty'},
        {type: 'auto', url: 'non-empty'},
        {type: 'unsupported', url: 'non-empty'}
      ],
      combinations: [[0, 2], [1, 2]]
    }, 'No supported combinations');
  });

  it('performs a revocation', (done) => {
    let cert = jose.base64url.encode(cachedCrypto.certReq.cert);
    let reason = 52;

    let gotRevokeCert = false;
    server.get('/directory').reply(200, directory)
          .head('/revoke-cert').reply(200, '', {'replay-nonce': 'foo'})
          .post('/revoke-cert')
          .reply((uri, jws, cb) => {
            gotRevokeCert = true;
            return jose.verify(jws)
              .then(verified => {
                assert.deepEqual(verified.payload, {
                  certificate: cert,
                  reason:      reason
                });
                cb(null, 200);
              })
              .catch(e => {
                cb(null, [501, e.message]);
              });
          });

    let client = new ACMEClient({
      accountKey:   accountKey,
      directoryURL: directoryURL
    });
    client.revokeCertificate(cert, reason)
      .then(() => {
        assert.isTrue(gotRevokeCert);
        done();
      })
      .catch(done);
  });

  it('rejects a revocation with a bad reason', (done) => {
    let cert = jose.base64url.encode(cachedCrypto.certReq.cert);
    let reason = 'not-an-integer';

    let client = new ACMEClient({
      accountKey:   accountKey,
      directoryURL: directoryURL
    });

    try {
      client.revokeCertificate(cert, reason);
      done(new Error('Revocation should reject a non-integer reason code'));
    } catch (e) {
      done();
    }
  });

  it('fails if there is no revoke-cert endpoint', (done) => {
    server.get('/directory').reply(200, {});

    let client = new ACMEClient({
      accountKey:   accountKey,
      directoryURL: directoryURL
    });
    client.registrationURL = 'non-null';
    client.revokeCertificate()
      .then(() => { done(new Error('New-app succeeded when it should not have')); })
      .catch(err => {
        assert.equal(err.message, 'Server does not have a certificate revocation endpoint');
        done();
      })
      .catch(done);
  });
});
