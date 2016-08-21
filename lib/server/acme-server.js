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
  'revoke-cert': '/revoke-cert',
  'key-change':  '/key-change'
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
  constructor(server, jwk, thumbprint, contact) {
    this.id = uuid.v4();
    this.status = 'good';
    this.key = jwk;
    this.thumbprint = thumbprint;
    this.contact = contact;
    this.url = server.makeURL(this);
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
  constructor(server, regID) {
    this.server = server;
    this.id = uuid.v4();
    this.status = 'pending';
    this.url = server.makeURL(this);
    this.regID = regID;
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
          let cert = new Certificate(this.server, this.regID, der);
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
  constructor(server, regID, thumbprint, name) {
    this.id = uuid.v4();
    this.regID = regID;
    this.status = 'pending';
    this.url = server.makeURL(this);
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
  constructor(server, regID, der) {
    this.id = uuid.v4();
    this.url = server.makeURL(this);
    this.regID = regID;
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

  delete(obj) {
    let type = obj.type();
    if (this.store[type]) {
      delete this.store[type][obj.id];
    }
  }

  regByThumbprint(thumbprint) {
    for (let key in this.store[Registration.type]) {
      if (this.store[Registration.type].hasOwnProperty(key)) {
        let reg = this.store[Registration.type][key];
        if ((reg.thumbprint === thumbprint)) {
          return reg;
        }
      }
    }
    return null;
  }

  authzFor(regID, name) {
    for (let key in this.store[Authorization.type]) {
      if (this.store[Authorization.type].hasOwnProperty(key)) {
        let authz = this.store[Authorization.type][key];
        if ((authz.regID === regID) &&
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
        if (app.regID !== authz.regID) {
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

  authorizedFor(regID, names) {
    let authzNames = {};
    for (let key in this.store[Authorization.type]) {
      if (this.store[Authorization.type].hasOwnProperty(key)) {
        let authz = this.store[Authorization.type][key];
        if (authz.regID === regID) {
          authzNames[authz.identifier.value] = true;
        }
      }
    }

    return names.filter(name => !authzNames[name]).length === 0;
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
    this.app.post(DIRECTORY_TEMPLATE['key-change'], (req, res) => this.keyChange(req, res));
    this.app.post(DIRECTORY_TEMPLATE['revoke-cert'], (req, res) => this.revokeCert(req, res));

    this.app.get('/:type/:id', (req, res) => this.fetch(req, res));
    this.app.get('/authz/:id/:index', (req, res) => this.fetchChallenge(req, res));
    this.app.post('/reg/:id', (req, res) => this.updateReg(req, res));
    this.app.post('/authz/:id', (req, res) => this.updateAuthz(req, res));
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

    // Filter GETs for registrations
    if (type === Registration.type) {
      res.status(401);
      res.set('content-type', 'application/problem+json');
      res.send(problem('unauthorized', 'GET requests not allowed for registrations'));
      return;
    }

    // Attempt to fetch
    let resource = this.db.get(type, id);
    if (!resource) {
      res.status(404);
      res.end();
      return;
    }

    let status = 200;
    let contentType = resource.contentType();
    let body = resource.marshal();

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
    let existing = this.db.regByThumbprint(thumbprint);
    if (existing) {
      res.status(409);
      res.set('location', this.makeURL(existing));
      res.end();
      return;
    }

    // Store a new registration
    let reg = new Registration(this, jwk, thumbprint, contact);
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
      res.end();
      return;
    }
    if (thumbprint !== reg.thumbprint) {
      res.status(401);
      res.send(problem('unauthorized', 'Unauthorized account key'));
      res.end();
      return;
    }

    // {{account-deactivation}}
    if (req.payload.status && req.payload.status === 'deactivated') {
      this.db.delete(reg);
      res.status(200);
      res.end();
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
    let reg = this.db.regByThumbprint(thumbprint);
    if (!reg) {
      res.status(401);
      res.send(problem('unauthorized', 'Unknown account key'));
      return;
    }

    // Create a stub application
    let app = new Application(this, reg.id);

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
      let authz = this.db.authzFor(reg.id, name);
      if (!authz) {
        authz = new Authorization(this, reg.id, reg.thumbprint, name);
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
    if (!authz) {
      res.status(404);
      res.end();
      return;
    }

    // Check that account key is appropriate for this authz
    let reg = this.db.regByThumbprint(req.accountKeyThumbprint);
    if (!reg || reg.id !== authz.regID) {
      res.status(401);
      res.send(problem('unauthorized', 'Unauthorized account key'));
      res.end();
      return;
    }

    if (!req.params.index) {
      // {{deactivating-an-authorization}}
      if (req.payload.status && req.payload.status === 'deactivated') {
        authz.status = 'deactivated';
        this.db.put(authz);
      }

      res.status(200);
      res.send(authz.marshal());
      res.end();
      return;
    }

    // If the authz has been finalized, no other changes are allowed
    if (authz.status !== 'pending') {
      res.status(403);
      res.send(authz.marshal());
      res.end();
      return;
    }

    // If we are updating a challenge, first check that it exists
    let index = parseInt(req.params.index);
    if (isNaN(index) || !(index in authz.challenges)) {
      res.status(404);
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

  // {{account-key-roll-over}}
  changeKey(req, res) {
    let inner;
    let outer = req;

    // Check that the payload of the request is a well-formed, valid JWS
    jose.verify(req.payload)
      .then(verified => {
        inner = verified;
        return inner.key.thumbprint();
      })
      .then(tpBuf => {
        let innerThumbprint = jose.base64url.encode(tpBuf);

        let reg = this.db.regByThumbprint(innerThumbprint);
        if (!reg) {
          res.status(403);
          res.send(problem('unauthorized', 'Inner account key is unregistered'));
          res.end();
          return;
        }

        let urlMatch = (inner.header.url === outer.header.url);
        let oldKeyMatch = (inner.payload.oldKey === innerThumbprint);
        let newKeyMatch = (inner.payload.newKey === outer.accountKeyThumbprint);
        let regMatch = (inner.payload.account === reg.url);
        if (!urlMatch || !oldKeyMatch || !newKeyMatch || !regMatch) {
          res.status(403);
          res.send(problem('unauthorized', 'Could not verify key-change request'));
          res.end();
          return;
        }

        reg.key = outer.accountKey;
        res.status(200);
        res.end;
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
    let reg = this.db.regByThumbprint(req.accountKeyThumbprint);
    let owner = (reg && reg.id === cert.regID);
    let authorized = this.db.authorizedFor(req.accountKeyThumbprint, pki.certNames(cert.der));

    let p = Promise.resolve(true);
    if (!owner && !authorized) {
      p = pki.certKeyThumbprint(cert.der)
        .then(tp => req.accountKeyThumbprint === tp);
    }

    p.then(ok => {
      if (!ok) {
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
    });
  }
}

module.exports = ACMEServer;
