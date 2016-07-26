// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const jose    = require('node-jose');
const express = require('express');
const Promise = require('bluebird');

class HTTP01Validation {
  static makeResponse(key, challenge) {
    return key.thumbprint()
      .then(thumbprintBuf => {
        let thumbprint = jose.util.base64url.encode(thumbprintBuf);
        let keyAuthorization = challenge.token + '.' + thumbprint;
        return {
          type:             HTTP01Validation.type,
          keyAuthorization: keyAuthorization
        };
      });
  }

  static respond(name, challenge, response, serverReady) {
    return new Promise(resolve => {
      let server;
      let app = express();
      app.get(`/.well-known/acme-challenge/${challenge.token}`, (req, res) => {
        res.send(response.keyAuthorization);
        res.end();
        server.close(() => {
          resolve(true);
        });
      });

      server = app.listen(HTTP01Validation.port);
      serverReady();
    })
    .timeout(HTTP01Validation.timeout);
  }
}

HTTP01Validation.type = 'http-01';
HTTP01Validation.port = 80;
HTTP01Validation.timeout = 1000;

module.exports = HTTP01Validation;
