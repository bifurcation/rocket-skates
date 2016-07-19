// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

class AutoChallenge {
  constructor() {
    this.status = 'pending';
    this.token = Math.random().toString().substring(2);
  }

  update(response) {
    if (!response.type || (response.type !== AutoChallenge.type) ||
        !response.token || (response.token !== this.token)) {
      this.status = 'invalid';
    } else {
      this.status = 'valid';
    }

    return Promise.resolve();
  }

  toJSON() {
    return {
      type:   AutoChallenge.type,
      status: this.status,
      token:  this.token
    };
  }
}

AutoChallenge.type = 'auto';

module.exports = AutoChallenge;
