// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert          = require('assert');
const TransportClient = require('./transport-client');

function validateReg(reg, key, contact, agreement) {
  if (!reg || !reg.key) {
    throw new Error('"key" field omitted from registration object');
  }

  try {
    assert.deepEqual(reg.key, key.toJSON());
  } catch (e) {
    throw new Error('Incorrect key in registration');
  }

  if (contact) {
    try {
      assert.deepEqual(contact, reg.contact);
    } catch (e) {
      throw new Error('Incorrect contact in registration');
    }
  }

  if (agreement && (reg.agreement !== agreement)) {
    throw new Error('Incorrect agreement in registration');
  }
}

class ACMEClient {
  // Caller needs to provide:
  //
  // * ACME server directory URL
  // * Account key (?)
  // * ValidationTypes
  // * Set callbacks for various protocol events within the overall calls:
  //   * User events
  //     * Agreement to terms
  //     * OOB requirement
  //   * Protocol events?
  //     * Got new registration
  //     * Got new application
  //     * Got authorization
  constructor(options) {
    options = options || {};

    if (!options.directoryURL) {
      throw new TypeError('Directory URL required');
    }

    this.directoryURL = options.directoryURL;
    this.client = new TransportClient(options);
  }

  directory() {
    if (this._directory) {
      return Promise.resolve(this._directory);
    }

    return TransportClient.get(this.directoryURL)
      .then(response => {
        this._directory = response.body;
        return response.body;
      });
  }

  register(contact) {
    return this.directory()
      .then(directory => {
        if (!directory['new-reg']) {
          throw new Error('Server does not have a new-registration endpoint');
        }

        return this.client.post(directory['new-reg'], {contact: contact});
      })
      .then(reg => {
        if (!reg.location) {
          throw new Error('No Location header in new-registration response');
        }
        this.registrationURL = reg.location;

        validateReg(reg.body, this.client.accountKey, contact);

        let terms = reg.links['terms-of-service'];
        if (terms && this.agreementCallback) {
          if (!this.agreementCallback(reg, terms.url)) {
            throw new Error('User did not agree to terms');
          }

          return this.client.post(this.registrationURL, {agreement: terms.url})
            .then(reg2 => {
              validateReg(reg2.body, this.client.accountKey, contact, terms.url);
              return reg2;
            });
        }

        return reg;
      });
  }
}

module.exports = ACMEClient;
