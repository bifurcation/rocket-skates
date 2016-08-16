// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const uuid            = require('node-uuid');
const jose            = require('../jose');
const pki             = require('../pki');
const TransportServer = require('./transport-server');

const DIRECTORY_TEMPLATE = {
  'directory':   '/directory',
  'new-reg':     '/new-reg',
  'new-app':     '/new-app',
  'revoke-cert': '/revoke-cert'
};

// * Class per object type
// * Each object has static type() method
// * Each object has an ID field.
//  * For registrations, this is thumbprint of the acct key
// * Format of URLs is $BASE/$TYPE/$ID

function select(obj, fields) {
  let out = {};
  for (let field of fields) {
    if (obj[field]) {
      out[field] = obj[field];
    }
  }
  return out;
}

// {{registration-objects}}
class Registration {
  constructor(id, jwk, contact) {
    this.id = id;
    this.status = 'good';
    this.key = jwk;
    this.contact = contact;
  }

  type() {
    return Registration.type;
  }

  contentType() {
    return Registration.contentType;
  }

  marshal() {
    return select(this, Registration.publicFields);
  }
}

Registration.type = 'reg';
Registration.contentType = 'application/json';
Registration.publicFields = [
  'key',
  'status',
  'contact',
  'agreement'
];

// {{application-objects}}
class Application {
  constructor(server, thumbprint) {
    this.server = server;
    this.id = uuid.v4();
    this.status = 'pending';
    this.url = server.makeURL(this);
    this.thumbprint = thumbprint;
    this.requirements = [];
  }

  type() {
    return Application.type;
  }

  contentType() {
    return Application.contentType;
  }

  issueIfReady() {
    let unfulfilled = this.requirements.filter(req => (req.status !== 'valid'));
    if (unfulfilled.length === 0) {
      this.status = 'valid'; // XXX: Should probably move this to updateAppsFor()
      return this.server.CA.issue(this)
        .then(der => {
          let cert = new Certificate(this.server, this.thumbprint, der);
          this.certificate = cert.url;
          this.server.db.put(cert);
          return this;
        });
    }
    return Promise.resolve(this);
  }

  marshal() {
    return select(this, Application.publicFields);
  }
}

Application.type = 'app';
Application.contentType = 'application/json';
Application.publicFields = [
  'status',
  'expires',
  'csr',
  'notBefore',
  'notAfter',
  'requirements',
  'certificate'
];

// {{authorization-objects}}
class Authorization {
  constructor(server, thumbprint, name) {
    this.id = uuid.v4();
    this.status = 'pending';
    this.url = server.makeURL(this);
    this.thumbprint = thumbprint;
    this.identifier = {
      type:  'dns',
      value: name
    };

    let offset = server.policy.authzExpirySeconds * 1000;
    let expires = new Date();
    expires.setTime(expires.getTime() + offset);
    this.expires = expires;

    this.challengeObj = [];
    for (let challengeType of server.challengeTypes) {
      this.challengeObj.push(new challengeType());
    }

    this.update();
  }

  update() {
    this.challenges = this.challengeObj.map((x, i) => {
      let obj = x.toJSON();
      obj.url = this.url + '/' + i.toString();
      return obj;
    });

    let now = new Date();
    let validChallenges = this.challenges.filter(x => (x.status === 'valid'));
    let allInvalid = this.challenges.map(x => x.status === 'invalid').reduce((x, y) => x && y);
    if ((this.expires < now) || allInvalid)  {
      this.status = 'invalid';
    } else if (validChallenges.length > 0) {
      this.status = 'valid';
    }
  }

  type() {
    return Authorization.type;
  }

  contentType() {
    return Authorization.contentType;
  }

  marshal() {
    this.update();
    return select(this, Authorization.publicFields);
  }

  asRequirement() {
    return {
      type:   'authorization',
      status: this.status,
      url:    this.url
    };
  }
}

Authorization.type = 'authz';
Authorization.contentType = 'application/json';
Authorization.publicFields = [
  'identifier',
  'status',
  'expires',
  'challenges',
  'combinations'
];

class Certificate {
  constructor(server, thumbprint, der) {
    this.id = uuid.v4();
    this.url = server.makeURL(this);
    this.thumbprint = thumbprint;
    this.der = der;
  }

  type() {
    return Certificate.type;
  }

  contentType() {
    return Certificate.contentType;
  }

  marshal() {
    return this.der;
  }
}

Certificate.type = 'cert';
Certificate.contentType = 'application/pkix-cert';

class DB {
  constructor() {
    this.store = {};
  }

  put(obj) {
    let type = obj.type();
    if (!this.store[type]) {
      this.store[type] = {};
    }
    this.store[type][obj.id] = obj;
  }

  get(type, id) {
    if (!this.store[type]) {
      return null;
    }
    return this.store[type][id];
  }

  authzFor(thumbprint, name) {
    for (let key in this.store[Authorization.type]) {
      if (this.store[Authorization.type].hasOwnProperty(key)) {
        let authz = this.store['authz'][key];
        if ((authz.thumbprint === thumbprint) &&
            (authz.identifier.value === name)) {
          return authz;
        }
      }
    }
    return null;
  }

  updateAppsFor(authz) {
    let dependencies = [];
    for (let key in this.store[Application.type]) {
      if (this.store[Application.type].hasOwnProperty(key)) {
        let app = this.store[Application.type][key];
        if (app.thumbprint !== authz.thumbprint) {
          continue;
        }

        app.requirements.map(req => {
          if (req.type === 'authorization' && req.url === authz.url) {
            req.status = authz.status;
          }
        });
        this.put(app);
        dependencies.push(app);
      }
    }

    return Promise.all(dependencies.map(app => app.issueIfReady()));
  }

  certByValue(certB64url) {
    let der = jose.base64url.decode(certB64url);

    for (let key in this.store[Certificate.type]) {
      if (this.store[Certificate.type].hasOwnProperty(key)) {
        let cert = this.store[Certificate.type][key];
        if (der.equals(cert.der)) {
          return cert;
        }
      }
    }

    return null;
  }
}

// {{errors}}
function problem(type, title, description) {
  return {
    type:        'urn:ietf:params:acme:error:' + type,
    title:       title,
    description: description
  };
}

class ACMEServer {
  constructor(options) {
    options = options || {};
    let host = options.host || 'localhost';
    let port = options.port || 80;
    let basePath = options.basePath || '';

    // Set policy preferences
    this.policy = {
      authzExpirySeconds: options.authzExpirySeconds,
      maxValiditySeconds: options.maxValiditySeconds,
      allowedExtensions:  options.allowedExtensions,
      requireOOB:         options.requireOOB,
      challenges:         {
        dns:    options.dnsChallenge,
        http:   options.httpChallenge,
        tlssni: options.tlssniChallenge,
        auto:   options.autoChallenge
      }
    };

    // Import challenges from caller preferences
    this.challengeTypes = [];
    if (!options.challengeTypes || options.challengeTypes.length === 0) {
      throw new Error('Cannot create a server without challenge types');
    }
    for (let challengeType of options.challengeTypes) {
      if ((typeof(challengeType.prototype.update) !== 'function') ||
          (typeof(challengeType.prototype.toJSON) !== 'function')) {
        throw new Error('ChallengeType does not have required methods');
      }

      this.challengeTypes.push(challengeType);
    }

    // Set up a CA and a transport-level server
    this.CA = options.CA || new pki.CA();
    this.transport = new TransportServer();

    // Set the base URL, so we can construct others
    switch (port) {
      case 443:  this.baseURL = `https://${host}${basePath}`; break;
      default:
        this.baseURL = `https://${host}:${port}${basePath}`;
        this.app.locals.port = port;
        break;
    }

    // Set up a database
    this.db = new DB();

    // Initialize the directory object
    this._directory = {'meta': {}};
    for (let name in DIRECTORY_TEMPLATE) {
      if (DIRECTORY_TEMPLATE.hasOwnProperty(name)) {
        this._directory[name] = this.baseURL + DIRECTORY_TEMPLATE[name];
      }
    }

    // {{resources}} "server MUST have exactly one resource for each function"
    this.app.get(DIRECTORY_TEMPLATE['directory'], (req, res) => this.directory(req, res));
    this.app.post(DIRECTORY_TEMPLATE['new-reg'], (req, res) => this.newReg(req, res));
    this.app.post(DIRECTORY_TEMPLATE['new-app'], (req, res) => this.newApp(req, res));
    this.app.post(DIRECTORY_TEMPLATE['revoke-cert'], (req, res) => this.revokeCert(req, res));

    this.app.get('/:type/:id', (req, res) => this.fetch(req, res));
    this.app.get('/authz/:id/:index', (req, res) => this.fetchChallenge(req, res));
    this.app.post('/reg/:id', (req, res) => this.updateReg(req, res));
    this.app.post('/authz/:id/:index', (req, res) => this.updateAuthz(req, res));
  }

  get app() {
    return this.transport.app;
  }

  get terms() {
    return this._directory.meta['terms-of-service'];
  }

  set terms(url) {
    this._directory.meta['terms-of-service'] = url;
  }

  // GET request handlers

  // {{directory}}
  directory(req, res) {
    res.set('content-type', 'application/json');
    res.json(this._directory);
    res.end();
  }

  // {{downloading-the-certificate}}
  fetch(req, res) {
    let type = req.params.type;
    let id = req.params.id;

    // Attempt to fetch
    let status = 200;
    let contentType = 'application/json';
    let resource = this.db.get(type, id);
    let body;
    if (resource) {
      contentType = resource.contentType();
      body = resource.marshal();
    }

    // Overwrite with errors if necessary
    if (type === Registration.type) {
      status = 401;
      body = problem('unauthorized', 'GET requests not allowed for registrations');
      contentType = 'application/problem+json';
    } else if (!body) {
      status = 404;
      body = '';
      contentType = '';
    }

    // Note revocation status for certificate resources
    if (type === Certificate.type && resource.revoked) {
      res.set('revocation-reason', resource.revocationReason);
    }

    res.status(status);
    res.set('content-type', contentType);
    res.send(body);
    res.end();
  }

  fetchChallenge(req, res) {
    let authz = this.db.get(Authorization.type, req.params.id);
    let index = parseInt(req.params.index);
    if (!authz || isNaN(index) || !(index in authz.challenges)) {
      res.status(404);
      res.end();
      return;
    }

    authz.update();
    this.db.put(authz);

    res.status(200);
    res.send(authz.challenges[index]);
  }

  // POST request handlers

  makeURL(obj) {
    let type = obj.type();
    let id = obj.id;
    return `${this.baseURL}/${type}/${id}`;
  }

  // {{registration}}
  newReg(req, res) {
    let jwk = req.accountKey;
    let contact = req.payload.contact;
    let thumbprint = req.accountKeyThumbprint;

    // Check for existing registrations
    let existing = this.db.get(Registration.type, thumbprint);
    if (existing) {
      res.status(409);
      res.set('location', this.makeURL(existing));
      res.end();
      return;
    }

    // Store a new registration
    let reg = new Registration(thumbprint, jwk, contact);
    this.db.put(reg);
    res.status(201);
    res.set('location', this.makeURL(reg));
    if (this.terms) {
      res.links({'terms-of-service': this.terms});
    }
    res.set('content-type', reg.contentType());
    res.send(reg.marshal());
  }

  // {{registration}}
  updateReg(req, res) {
    // Check that account key is registered
    let thumbprint = req.accountKeyThumbprint;
    let reg = this.db.get(Registration.type, req.params.id);
    if (!reg) {
      res.status(404);
      res.send(problem('unauthorized', 'Unknown registration'));
      return;
    }
    if (thumbprint !== req.params.id) {
      res.status(401);
      res.send(problem('unauthorized', 'Unauthorized account key'));
      return;
    }

    if (req.payload.contact) {
      reg.contact = req.payload.contact;
    }
    if (req.payload.agreement) {
      if (req.payload.agreement !== this.terms) {
        res.status(400);
        res.send(problem('malformed', 'Incorrect agreement URL'));
        return;
      }
      reg.agreement = req.payload.agreement;
    }
    this.db.put(reg);

    res.status(200);
    if (this.terms) {
      res.links({'terms-of-service': this.terms});
    }
    res.send(reg.marshal());
  }

  // {{applying-for-certificate-issuance}}
  newApp(req, res) {
    // Check that account key is registered
    let thumbprint = req.accountKeyThumbprint;
    let reg = this.db.get(Registration.type, thumbprint);
    if (!reg) {
      res.status(401);
      res.send(problem('unauthorized', 'Unknown account key'));
      return;
    }

    // Create a stub application
    let app = new Application(this, thumbprint);

    // Parse the request elements, determine if it's acceptable
    let names;
    try {
      if (!req.payload.csr) {
        throw new Error('CSR must be provided');
      }

      names = pki.checkCSR(pki.parseCSR(req.payload.csr));
      app.csr = req.payload.csr;

      let notBefore;
      if (req.payload.notBefore) {
        notBefore = new Date(req.payload.notBefore);
        if (isNaN(notBefore.getTime())) {
          throw new Error('Invalid notBefore format');
        }
        app.notBefore = req.payload.notBefore;
      }

      let notAfter;
      if (req.payload.notAfter) {
        if (!app.notBefore) {
          throw new Error('notAfter provided without notBefore');
        }

        notAfter = new Date(req.payload.notAfter);
        if (isNaN(notAfter.getTime())) {
          throw new Error('Invalid notAfter format');
        }
        app.notAfter = req.payload.notAfter;
      }

      if (notBefore && notAfter &&
        (notAfter - notBefore > 1000 * pki.CA.maxValiditySeconds)) {
        throw new Error('Requested duration is too long');
      }
    } catch (e) {
      res.status(400);
      res.send(problem('malformed', 'Invalid new application', e.message));
      return;
    }

    // Assemble authorization requirements
    for (let name of names) {
      let authz = this.db.authzFor(thumbprint, name);
      if (!authz) {
        authz = new Authorization(this, thumbprint, name);
      }
      this.db.put(authz);
      app.requirements.push(authz.asRequirement());
    }

    // XXX(#20): Set OOB if required by policy

    this.db.put(app);

    // If we're OK to issue, go ahead and do so, then return
    // the application.
    app.issueIfReady()
      .then(() => {
        res.status(201);
        res.set('location', app.url);
        res.send(app.marshal());
      });
  }

  // {{responding-to-challenges}}
  updateAuthz(req, res) {

    // Check that the requested authorization and challenge exist
    let authz = this.db.get(Authorization.type, req.params.id);
    let index = parseInt(req.params.index);
    if (!authz || isNaN(index) || !(index in authz.challenges)) {
      res.status(404);
      res.end();
      return;
    }

    // Check that account key is appropriate for this authz
    let thumbprint = req.accountKeyThumbprint;
    if (thumbprint !== authz.thumbprint) {
      res.status(401);
      res.send(problem('unauthorized', 'Unauthorized account key'));
      res.end();
      return;
    }

    // Asynchronously update the challenge, the authorization, and any
    // applications that depend on the authorization.
    //
    // NB: It's nice for testing to have the response only go back after
    // everything is updated, since then you know that anything that's going to
    // be issued has been.  However, updates are slow, so we might want to go
    // async ultimately.
    authz.challengeObj[index].update(req.payload)
      .then(() => {
        authz.update();
      })
      .then(() => {
        return this.db.updateAppsFor(authz);
      })
      .then(() => {
        res.status(200);
        res.send(authz.challenges[index]);
        res.end();
      });
  }

  // {{certificate-revocation}}
  revokeCert(req, res) {
    // Check that the certificate is known to this server
    let cert = this.db.certByValue(req.payload.certificate);
    if (!cert) {
      res.status(403);
      res.send(problem('unauthorized', 'Unknown certificate'));
      res.end();
      return;
    }

    // Check that account key is appropriate for this authz
    // * Account that created the certificate
    // * Account that is authorized for the names in the certificate
    // * Public key in the certificate
    let owner = (req.accountKeyThumbprint === cert.thumbprint);
    let authorized = false; // TODO
    let certKey = false;    // TODO
    if (!owner && !authorized && !certKey) {
      res.status(403);
      res.send(problem('unauthorized', 'Client key not authorized for this certificate'));
      res.end();
      return;
    }

    // Mark the certificate as revoked
    let reason = parseInt(req.payload.reason);
    if (isNaN(reason)) {
      reason = 0;
    }
    cert.revoked = true;
    cert.revocationReason = reason;
    this.db.put(cert);

    res.status(200);
    res.end();
  }
}

module.exports = ACMEServer;
