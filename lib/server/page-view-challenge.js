// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// {{out-of-band}}

'use strict';

const crypto  = require('crypto');
const express = require('express');
const Promise = require('bluebird');

Promise.config({cancellation: true});

class PageViewChallenge {
  constructor() {
    this.status = 'pending';

    let randomPath = crypto.randomBytes(32).toString('base64')
                           .replace(/\//g, '_').replace(/\+/g, '-')
                           .replace(/=/g, '');

    this.href = `http://localhost:${PageViewChallenge.port}/${randomPath}`;

    let server;
    this._server = new Promise((resolve, reject, onCancel) => {
      let app = express();
      app.get(`/${randomPath}`, (req, res) => {
        res.status(200);
        res.end();
        resolve();
      });

      server = app.listen(PageViewChallenge.port);
      onCancel(() => { server.close(); });
    })
      .timeout(PageViewChallenge.timeout)
      .then(() => {
        // XXX: Concerned about a race condition with the update() method here,
        // but it looks like it can only be triggered if the event loop
        // alternates:
        //
        // 1. Get HTTP request and resolve
        // 2. update(bad response)
        // 3. This block
        //
        // Not sure if that's possible or not.
        this.status = 'valid';
        this.validated = new Date();
      })
      .catch(() => {
        this.status = 'invalid';
      })
      .finally(() => {
        return new Promise(resolve => {
          server.close(() => { resolve(this); });
        });
      });
  }

  update(response) {
    if (!response.type || (response.type !== PageViewChallenge.type)) {
      this.final = true;
      this.status = 'invalid';
      this._server.cancel();
      return Promise.resolve(this);
    }

    return this._server;
  }

  toJSON() {
    let obj = {
      type:      PageViewChallenge.type,
      href:      this.href,
      validated: this.validated
    };

    return obj;
  }
}

PageViewChallenge.type = 'oob-01';
PageViewChallenge.port = 80;
PageViewChallenge.timeout = 2000;

module.exports = PageViewChallenge;
