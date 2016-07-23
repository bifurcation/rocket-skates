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

function validateApp(/* todo */) {
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

  _fulfillAuthorization(authzURL) {
    return TransportClient.get(authzURL)
      .then(() => true);
  }

  requestCertificate(csr, notBefore, notAfter) {
    if (!this.registrationURL) {
      return Promise.reject(new Error('Cannot request a certificate without registering'));
    }

    let applicationURL;
    let currentApp;

    return this.directory()
      .then(directory => {
        if (!directory['new-app']) {
          throw new Error('Server does not have a new-application endpoint');
        }

        return this.client.post(directory['new-app'], {
          csr:       csr,
          notBefore: notBefore,
          notAfter:  notAfter
        });
      })
      .then(app => {
        if (!app.location) {
          throw new Error('No Location header in new-registration response');
        }
        applicationURL = app.location;
        currentApp = app.body;

        validateApp(app.body, csr, notBefore, notAfter);

        if (app.body.certificate) {
          return TransportClient.get(app.body.certificate);
        }

        let validations = currentApp.requirements.map(req => {
          if (req.type === 'authorization') {
            return this._fulfillAuthorization(req.url);
          }

          // XXX(#20) Add support for OOB requirements
          throw new Error('Unsupported requirement type:', req.type);
        });
        return Promise.all(validations);
      })
      .then(() => {
        let validAndHasCert = (app => {
          return (app.body.status === 'valid') && (app.body.certificate);
        });
        return TransportClient.poll(applicationURL, validAndHasCert);
      })
      .then(app => {
        if (!app.body.certificate) {
          throw new Error('No certificate provided for valid application');
        }

        return TransportClient.get(app.body.certificate);
      });
  }
}

module.exports = ACMEClient;
