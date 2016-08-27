// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert              = require('chai').assert;
const express             = require('express');
const OutOfBandValidation = require('../lib/client/out-of-band-validation.js');

OutOfBandValidation.headless = true;

describe('oob-01 validation', () => {
  it('creates a correct response', (done) => {
    OutOfBandValidation.makeResponse()
      .then(response => {
        assert.deepEqual(response, {type: OutOfBandValidation.type});
        done();
      })
      .catch(done);
  });


  it('fulfills an oob-01 challenge', (done) => {
    let port = 8888;
    let path = '/oob';
    let challenge = {url: `http://localhost:${port}${path}`};

    let gotRequest = false;
    let app = express();
    app.get(path, (req, res) => {
      gotRequest = true;
      res.status(200);
      res.send('Answer me these questions three...');
      res.end();
    });

    let server;
    new Promise(resolve => { server = app.listen(port, resolve); })
      .then(() => { return OutOfBandValidation.respond(null, challenge); })
      .then(() => { return new Promise(resolve => { server.close(resolve); }); })
      .then(() => {
        assert.isTrue(gotRequest);
        done();
      })
      .catch(done);
  });
});
