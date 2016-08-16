// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const jose  = require('../../lib/jose');
const pem   = require('pem');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const certOptions = {
  commonName: 'example.com',
  selfSigned: true
};

let serverOptions;
let key;

module.exports = {
  get tlsConfig() {
    if (serverOptions) {
      return Promise.resolve(serverOptions);
    }

    return new Promise((resolve, reject) => {
      pem.createCertificate(certOptions, (err, obj) => {
        if (err) {
          reject(err);
          return;
        }

        serverOptions = {
          key:  obj.serviceKey,
          cert: obj.certificate
        };
        resolve(serverOptions);
      });
    });
  },

  get key() {
    if (key) {
      return Promise.resolve(key);
    }

    return jose.newkey()
      .then(k => {
        key = k;
        return k;
      });
  }
};
