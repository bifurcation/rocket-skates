// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const jose = require('../../lib/jose');

class MockClient {
  key() {
    if (this._key) {
      return Promise.resolve(this._key);
    }
    return jose.newkey()
      .then(k => {
        this._key = k;
        return k;
      });
  }

  makeJWS(nonce, url, payload) {
    return this.key()
      .then(k => jose.sign(k, payload, {
        nonce: nonce,
        url:   url
      }));
  }
}

module.exports = MockClient;
