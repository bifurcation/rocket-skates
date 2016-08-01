// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const dns     = require('native-dns');
const crypto  = require('crypto');
const Promise = require('bluebird');
const jose    = require('../jose');

const serverCloseWaitMilli = 250;

class DNS01Validation {
  static makeResponse(key, challenge) {
    return key.thumbprint()
      .then(thumbprintBuf => {
        let thumbprint = jose.base64url.encode(thumbprintBuf);
        let keyAuthorization = challenge.token + '.' + thumbprint;
        return {
          type:             DNS01Validation.type,
          keyAuthorization: keyAuthorization
        };
      });
  }

  static respond(name, challenge, response, serverReady) {
    let keyAuthorizationHashBuf = crypto.createHash('sha256')
                                        .update(response.keyAuthorization, 'utf8')
                                        .digest();
    let keyAuthorizationHash = jose.base64url.encode(keyAuthorizationHashBuf);
    let recordName = '_acme-challenge.' + name;
    let record = dns.TXT({
      name: recordName,
      data: [keyAuthorizationHash],
      ttl:  600
    });

    let server = dns.createServer();

    return new Promise(resolve => {
      server.on('request', (req, res) => {
        // XXX: If there is no question, then there will be no response, because
        // this will throw.  That's OK, because a request with zero questions is
        // not a valid DNS request.
        let question = req.question[0];
        if ((question.class !== dns.consts.NAME_TO_QCLASS.IN) ||
            (question.type !== dns.consts.NAME_TO_QTYPE.TXT) ||
            (question.name !== recordName)) {
          res.header.rcode = dns.consts.NAME_TO_RCODE.NOTFOUND;
        } else {
          res.answer.push(record);
        }

        // XXX: Race condition here.  If we close the server immediately, then
        // the response is never sent.
        Promise.resolve(res.send())
          .then(() => { return Promise.delay(serverCloseWaitMilli); })
          .then(() => { server.close(); });
      });

      server.on('close', () => {
        resolve(true);
      });

      server.serve(DNS01Validation.port);
      serverReady();
    })
    .timeout(DNS01Validation.timeout);
  }
}

DNS01Validation.type = 'dns-01';
DNS01Validation.port = 53;
DNS01Validation.timeout = 1000;

module.exports = DNS01Validation;
