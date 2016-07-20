// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert            = require('chai').assert;
const Promise           = require('bluebird');
const pem               = require('pem');
const tls               = require('tls');
const TLSSNI02Challenge = require('../lib/challenges/tls-sni-challenge.js');

function newServer(names) {
  let options = {
    commonName: names[0],
    altNames:   names,
    selfSigned: true
  };

  return new Promise((resolve, reject) => {
    pem.createCertificate(options, (err, obj) => {
      if (err) {
        reject(err);
      } else {
        resolve(obj);
      }
    });
  }).then(obj => {
    let opts = {
      key:  obj.serviceKey,
      cert: obj.certificate
    };
    let server = tls.createServer(opts, socket => {
      server.gotRequest = true;
      socket.end();
    });
    return server;
  });
}

const thumbprint = 'p3wl28h-9g3g1r6eIGORS5usGW79TUjL6fo_T5xRhAQ';
const name = 'example.com';

const port = 4430;
TLSSNI02Challenge.host = 'localhost';
TLSSNI02Challenge.port = port;



describe('tls-sni-02 challenge', () => {
  it('updates and does a query', done => {
    let challenge = new TLSSNI02Challenge(name, thumbprint);
    assert.equal(challenge.status, 'pending');

    let error;
    let server;
    let response = {
      type:             TLSSNI02Challenge.type,
      keyAuthorization: challenge._keyAuthorization
    };
    newServer([name, challenge._sanA, challenge._sanB])
      .then(srv => {
        server = srv;
        server.listen(port);
      })
      .then(() => { return challenge.update(response); })
      .then(() => {
        assert.isTrue(server.gotRequest);
        assert.equal(challenge.status, 'valid');
      })
      .catch(err => { error = err; })
      .then(() => {
        if (server) {
          server.close(() => { done(error); });
        } else {
          done(error);
        }
      });
  });

  it('rejects a response with the wrong type', done => {
    let challenge = new TLSSNI02Challenge(name, thumbprint);
    let response = {
      type:             'not-tls-sni',
      keyAuthorization: challenge._keyAuthorization
    };

    challenge.update(response)
      .then(() => {
        assert.equal(challenge.status, 'invalid');
        done();
      })
      .catch(done);
  });

  it('rejects a response with the wrong keyAuthorization', done => {
    let challenge = new TLSSNI02Challenge(name, thumbprint);
    let response = {
      type:             TLSSNI02Challenge.type,
      keyAuthorization: challenge._keyAuthorization + '-not'
    };

    challenge.update(response)
      .then(() => {
        assert.equal(challenge.status, 'invalid');
        done();
      })
      .catch(done);
  });

  it('rejects a bad validation response', done => {
    let challenge = new TLSSNI02Challenge(name, thumbprint);
    assert.equal(challenge.status, 'pending');

    let error;
    let server;
    let response = {
      type:             TLSSNI02Challenge.type,
      keyAuthorization: challenge._keyAuthorization
    };
    newServer([name, challenge._sanA]) // no SAN B
      .then(srv => {
        server = srv;
        server.listen(port);
      })
      .then(() => { return challenge.update(response); })
      .then(() => {
        assert.isTrue(server.gotRequest);
        assert.equal(challenge.status, 'invalid');
      })
      .catch(err => { error = err; })
      .then(() => {
        if (server) {
          server.close(() => { done(error); });
        } else {
          done(error);
        }
      });
  });

  it('serializes properly', done => {
    let challenge = new TLSSNI02Challenge(name, thumbprint);
    let serialized = challenge.toJSON();

    assert.property(serialized, 'type');
    assert.property(serialized, 'status');
    assert.property(serialized, 'token');
    assert.notProperty(serialized, 'keyAuthorization');

    let error;
    let server;
    let response = {
      type:             TLSSNI02Challenge.type,
      keyAuthorization: challenge._keyAuthorization
    };
    newServer([name, challenge._sanA, challenge._sanB])
      .then(srv => {
        server = srv;
        server.listen(port);
      })
      .then(() => { return challenge.update(response); })
      .then(() => {
        let serialized2 = challenge.toJSON();

        assert.property(serialized2, 'type');
        assert.property(serialized2, 'status');
        assert.property(serialized2, 'token');
        assert.property(serialized2, 'keyAuthorization');

        assert.equal(serialized2.type, serialized.type);
        assert.equal(serialized2.token, serialized.token);
      })
      .catch(err => { error = err; })
      .then(() => {
        if (server) {
          server.close(() => { done(error); });
        } else {
          done(error);
        }
      });
  });
});
