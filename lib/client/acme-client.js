// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const deepEqual       = require('deep-equal');
const TransportClient = require('./transport-client');

const POLL_LIMIT = 30;
const POLL_DELAY = 500;

// {{registration-objects}}
function validateReg(reg, key, contact, agreement) {
  if (!reg.key) {
    throw new Error('"key" field omitted from registration object');
  }

  if (!deepEqual(reg.key, key.toJSON())) {
    throw new Error('Incorrect key in registration');
  }

  if (contact && !deepEqual(contact, reg.contact)) {
    throw new Error('Incorrect contact in registration');
  }

  if (agreement && (reg.agreement !== agreement)) {
    throw new Error('Incorrect agreement in registration');
  }
}

// {{application-objects}}
function validateApp(app, csr, notBefore, notAfter) {
  if (!app.csr || !app.status || !app.requirements) {
    throw new Error('Application is missing a required field');
  }

  if (app.csr !== csr) {
    throw new Error('Incorrect CSR in application');
  }

  if (notBefore && (app.notBefore !== notBefore.toJSON())) {
    throw new Error('Incorrect notBefore in application');
  }

  if (notAfter && (app.notAfter !== notAfter.toJSON())) {
    throw new Error('Incorrect notAfter in application');
  }

  if (!(app.requirements instanceof Array) || (app.requirements.length === 0)) {
    throw new Error('No requirements in application');
  }
}

// {{authorization-objects}}
function validateAuthz(authz) {
  if (!authz.identifier || !authz.status || !authz.challenges) {
    throw new Error('Authorization is missing a required field');
  }

  if (!authz.identifier.type || !authz.identifier.value) {
    throw new Error('Authorization identifier is malformed');
  }

  if (!(authz.challenges instanceof Array) || (authz.challenges.length === 0)) {
    throw new Error('No challenges provided in application');
  }

  for (let chall of authz.challenges) {
    if (!chall.type || !chall.url) {
      throw new Error('Missing field in challenge');
    }
  }

  if (authz.combinations) {
    if (!(authz.combinations instanceof Array) || (authz.combinations.length === 0)) {
      throw new Error('Malformed combinations field in application');
    }

    authz.combinations.map(combo => {
      if (!(combo instanceof Array) || (combo.length === 0)) {
        throw new Error('Malformed combination value in application');
      }

      combo.map(i => {
        if ((typeof(i) !== 'number') || (i < 0) || (i >= authz.challenges.length)) {
          throw new Error('Combination value out of bounds');
        }
      });
    });
  }
}

class ACMEClient {
  constructor(options) {
    options = options || {};

    if (!options.directoryURL) {
      throw new TypeError('Directory URL required');
    }

    this.agreementCallback = options.agreementCallback;
    this.directoryURL = options.directoryURL;
    this.client = new TransportClient(options);

    this.validationTypes = {};
    if (options.validationTypes) {
      for (let validationType of options.validationTypes) {
        if ((typeof(validationType.makeResponse) !== 'function') ||
            (typeof(validationType.respond) !== 'function')) {
          throw new Error('ChallengeType does not have required methods');
        }

        this.validationTypes[validationType.type] = validationType;
      }
    }
  }

  // {{resources}} [NB: No client-side requirements]
  // {{directory}}
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

  // {{registration}}
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

  // {{responding-to-challenges}}
  _getAuthorization(authzURL) {
    return TransportClient.get(authzURL)
      .then(authzResponse => {
        let authz = authzResponse.body;
        validateAuthz(authz);

        let combinations = authz.combinations;
        if (!combinations) {
          combinations = authz.challenges.map((x, i) => [i]);
        }

        let allSupported = (combo => {
          return combo.map(i => (authz.challenges[i].type in this.validationTypes))
            .reduce((x, y) => x && y);
        });

        let makeValidations = (combo => {
          return combo.map(i => authz.challenges[i])
            .map(chall => {
              let val = this.validationTypes[chall.type];
              let response;
              return val.makeResponse(this.client.accountKey, chall)
                .then(res => {
                  response = res;
                  return this.client.post(chall.url, response);
                })
                .then(() => { return val.respond(chall, response); });
            });
        });

        for (let combo of combinations) {
          if (allSupported(combo)) {
            return Promise.all(makeValidations(combo));
          }
        }

        throw new Error('No supported combinations');
      });
  }

  // {{applying-for-certificate-issuance}}
  // {{downloading-the-certificate}}
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
          throw new Error('No Location header in new-application response');
        }
        applicationURL = app.location;
        currentApp = app.body;

        validateApp(app.body, csr, notBefore, notAfter);

        if (app.body.certificate) {
          return TransportClient.get(app.body.certificate);
        }

        let validations = currentApp.requirements.map(req => {
          if ((req.type === 'authorization') && (req.status === 'pending')) {
            return this._getAuthorization(req.url);
          }

          // XXX(#20) Add support for OOB requirements
          throw new Error('Unsupported requirement type: ' + req.type);
        });

        let validAndHasCert = (appRes => {
          return (appRes.body.status === 'valid') && (appRes.body.certificate);
        });
        return Promise.all(validations)
          .then(() => {
            return TransportClient.poll(applicationURL, validAndHasCert, POLL_LIMIT, POLL_DELAY);
          })
          .then(appRes => TransportClient.get(appRes.body.certificate, true));
      })
      .then(certRes => {
        // XXX(#22) Verify that the certificate provided by the server is valid
        return certRes.body;
      });
  }
}

module.exports = ACMEClient;
