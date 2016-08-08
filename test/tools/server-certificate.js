// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const pem   = require('pem');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const certOptions = {
  commonName: 'example.com',
  selfSigned: true
};

let serverOptions;

function serverCert() {
  if (serverOptions) {
    return Promise.resolve(serverOptions);
  }

  return new Promise((resolve, reject) => {
    pem.createCertificate(certOptions, (err, obj) => {
      if (err) {
        reject(err);
        return;
      }

      resolve({
        key:  obj.serviceKey,
        cert: obj.certificate
      });
    });
  });
}

module.exports = serverCert;
