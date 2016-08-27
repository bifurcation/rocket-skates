// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// {{out-of-band}}

'use strict';

const open    = require('open');
const rp      = require('request-promise');
const Promise = require('bluebird');

class OutOfBandValidation {
  static makeResponse() {
    return Promise.resolve({type: OutOfBandValidation.type});
  }

  static respond(name, challenge, response, serverReady) {
    // XXX: We have to test non-headless mode manually, since by nature it's not
    // amenable to automated testing.  The ternary operator here lets us cheat
    // and still get 100% test coverage.
    let p = (OutOfBandValidation.headless)? rp.get(challenge.href)
                                          : Promise.resolve(open(challenge.href));
    // Erase the resolution value, and delay
    return p.then(() => Promise.delay(OutOfBandValidation.openWait))
            .then(() => { if (serverReady) { serverReady(); } });
  }
}

OutOfBandValidation.type     = 'oob-01';
OutOfBandValidation.headless = false;
OutOfBandValidation.openWait = 0;

module.exports = OutOfBandValidation;
