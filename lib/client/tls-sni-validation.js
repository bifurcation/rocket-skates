// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// {{tls-with-server-name-indication-tls-sni}}

'use strict';

const crypto  = require('crypto');
const pem     = require('pem');
const tls     = require('tls');
const Promise = require('bluebird');
const jose    = require('../jose');

class TLSSNI02Validation {
  static makeResponse(key, challenge) {
    return key.thumbprint()
      .then(thumbprintBuf => {
        let thumbprint = jose.base64url.encode(thumbprintBuf);
        let keyAuthorization = challenge.token + '.' + thumbprint;
        return {
          type:             TLSSNI02Validation.type,
          keyAuthorization: keyAuthorization
        };
      });
  }

  static respond(name, challenge, response, serverReady) {
    let tokenHash = crypto.createHash('sha256')
                          .update(challenge.token, 'utf8')
                          .digest('hex').toLowerCase();
    // {{key-authorizations}}
    let keyAuthorizationHash = crypto.createHash('sha256')
                                     .update(response.keyAuthorization, 'utf8')
                                     .digest('hex').toLowerCase();

    let sanA1 = tokenHash.substr(0, 32);
    let sanA2 = tokenHash.substr(32);
    let sanB1 = keyAuthorizationHash.substr(0, 32);
    let sanB2 = keyAuthorizationHash.substr(32);

    let sanA = `${sanA1}.${sanA2}.acme.invalid`;
    let sanB = `${sanB1}.${sanB2}.acme.invalid`;

    // XXX: OpenSSL will not issue with sanA or sanB in the CN field, because it
    // thinks the name is too long.  So instead we use something meaningless.
    let options = {
      commonName: 'tls-sni.acme.invalid',
      altNames:   [sanA, sanB],
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
        socket.end();
        server.close();
      });

      serverReady();
      server.listen(TLSSNI02Validation.port);
    })
    .timeout(TLSSNI02Validation.timeout);
  }
}

TLSSNI02Validation.type = 'tls-sni-02';
TLSSNI02Validation.port = 332;
TLSSNI02Validation.timeout = 5000;

module.exports = TLSSNI02Validation;
