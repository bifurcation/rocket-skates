// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const crypto = require('crypto');
const tls    = require('tls');

class TLSSNI02Challenge {
  constructor(name, thumbprint) {
    this.status = 'pending';
    this.name = name;

    this.token = crypto.randomBytes(32).toString('base64')
                       .replace(/\//g, '_').replace(/\+/g, '-')
                       .replace(/=/g, '');
    this._keyAuthorization = this.token + '.' + thumbprint;

    let tokenHash = crypto.createHash('sha256')
                          .update(this.token, 'utf8')
                          .digest('hex').toLowerCase();
    let keyAuthorizationHash = crypto.createHash('sha256')
                                     .update(this._keyAuthorization, 'utf8')
                                     .digest('hex').toLowerCase();

    let sanA1 = tokenHash.substr(0, 32);
    let sanA2 = tokenHash.substr(32);
    let sanB1 = keyAuthorizationHash.substr(0, 32);
    let sanB2 = keyAuthorizationHash.substr(32);

    this._sanA = `${sanA1}.${sanA2}.acme.invalid`;
    this._sanB = `${sanB1}.${sanB2}.acme.invalid`;
  }

  update(response) {
    if (!response.type || (response.type !== TLSSNI02Challenge.type) ||
        !response.keyAuthorization ||
        (response.keyAuthorization !== this._keyAuthorization)) {
      this.status = 'invalid';
      return Promise.resolve(this);
    }

    this.keyAuthorization = this._keyAuthorization;

    let connectDomain = (TLSSNI02Challenge.host === 'auto') ? this.name : TLSSNI02Challenge.host;
    let options = {
      host:               connectDomain,
      servername:         this._sanA,
      port:               TLSSNI02Challenge.port,
      rejectUnauthorized: false
    };

    return new Promise((resolve, reject) => {
      let stream = tls.connect(options, () => {
        let san = stream.getPeerCertificate().subjectaltname;
        stream.end();
        if (!san) {
          reject(new Error('No SAN in peer certificate'));
          return;
        }

        let foundSANA = (san.indexOf(`DNS:${this._sanA}`) > -1);
        let foundSANB = (san.indexOf(`DNS:${this._sanB}`) > -1);
        if (!foundSANA || !foundSANB) {
          reject(new Error('Required SANs not found'));
          return;
        }

        this.status = 'valid';
        resolve(true);
      });
    }).catch(() => {
      this.status = 'invalid';
    });
  }

  toJSON() {
    let obj = {
      type:   TLSSNI02Challenge.type,
      status: this.status,
      token:  this.token
    };

    if (this.keyAuthorization) {
      obj.keyAuthorization = this.keyAuthorization;
    }

    return obj;
  }
}

TLSSNI02Challenge.type = 'tls-sni-02';
TLSSNI02Challenge.host = 'auto';
TLSSNI02Challenge.port = 443;

module.exports = TLSSNI02Challenge;
