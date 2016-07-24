// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

class AutoValidation {
  static respond(transport, challenge) {
    return transport.post(challenge.url, {token: challenge.token});
  }
}

AutoValidation.type = 'auto';

module.exports = AutoValidation;
