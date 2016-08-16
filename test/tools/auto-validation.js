// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

class AutoValidation {
  static makeResponse(key, challenge) {
    return Promise.resolve({
      type:  AutoValidation.type,
      token: challenge.token
    });
  }

  static respond() {}
}

AutoValidation.type = 'auto';

module.exports = AutoValidation;
