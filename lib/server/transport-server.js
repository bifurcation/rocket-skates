// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// {{message-transport}}

'use strict';

const express     = require('express');
const bodyParser  = require('body-parser');
const urlParse    = require('url');
const jose        = require('../jose');
const nonceSource = require('./nonce-source');

// This enforces a simple rate limit, allowing a bucket of requests that empties
// over the course of RateLimit.window milliseconds.
class RateLimit {
  constructor(size) {
    this.size = size;
    this.queue = [];
    this.nextOpen = new Date();
  }

  retryAfter() {
    let now = new Date();
    if (this.nextOpen < now) {
      return 0;
    }
    return Math.ceil((this.nextOpen - now) / 1000);
  }

  update() {
    let now = new Date();
    this.queue.push(now);
    while (now - this.queue[0] > RateLimit.window) {
      this.queue.shift();
    }

    if (this.queue.length >= this.size) {
      this.nextOpen.setTime(this.queue[0].getTime() + RateLimit.window);
    }
  }
}

RateLimit.window = 1000;

class NoopRateLimit {
  retryAfter() { return 0; }
  update() {}
}

class TransportServer {
  constructor(options) {
    options = options || {};

    this.app = express();
    this.nonces = new nonceSource();

    this.rateLimit = new NoopRateLimit();
    if (options.rateLimit > 0) {
      this.rateLimit = new RateLimit(options.rateLimit);
    }

    // Every POST should have a JSON (JWS) body
    this.app.use(bodyParser.json());

    // Apply a global rate limit and send a replay nonce on all responses
    this.app.all('/*', (req, res, next) => {
      // {{https-requests}}
      if (req.protocol !== 'https') {
        res.status(500);
        res.json({
          'type':  'urn:ietf:params:acme:error:malformed',
          'title': 'Mis-configured server; ACME requests must be HTTPS'
        });
        return;
      }

      // {{replay-nonce}}
      res.set('replay-nonce', this.nonces.get());
      next();
    });

    this.app.post('/*', (req, res, next) => {
      // {{rate-limits}}
      let retryAfter = this.rateLimit.retryAfter();
      if (retryAfter > 0) {
        res.status(403);
        res.set('retry-after', retryAfter);
        res.json({
          'type':  'urn:ietf:params:acme:error:rateLimited',
          'title': 'Please retry your request after some time'
        });
        return;
      }
      this.rateLimit.update();

      jose.verify(req.body)
        .then(result => {
          // {{request-authentication}}
          let nonce = result.header.nonce;
          let url = result.header.url;

          // {{replay-protection}}
          // {{nonce-nonce-jws-header-parameter}}
          if (!this.nonces.use(nonce)) {
            throw new Error(`Invalid nonce [${nonce}]`);
          }

          if (!this._checkURL(req, url)) {
            throw new Error(`Incorrect url value [${url}]`);
          }

          req.accountKey = result.key;
          req.header = result.header;
          req.payload = result.payload;
          return result.key.thumbprint();
        })
        .then(thumbprint => {
          req.accountKeyThumbprint = jose.base64url.encode(thumbprint);
          next();
        })
        .catch(err => {
          res.status(400);
          res.json({
            'type':   'urn:ietf:params:acme:error:malformed',
            'title':  'Request failed transport-level validation',
            'detail': err.message
          });
        });
    });
  }

  // XXX: If this app is running on a non-standard port, the caller MUST set
  // server.app.locals.port to the port number before starting the server.
  // {{request-uri-integrity}}
  // {{url-url-jws-header-parameter}}
  _checkURL(req, url) {
    let parsed = urlParse.parse(url);
    let host = req.hostname;
    let port = req.app.locals.port;
    let hostport = (port)? `${host}:${port}` : host;

    // XXX: This just compares the 'url' field to the request parameters.
    // It thus assumes that routing is working correctly.
    // {{https-requests}}
    return (parsed.protocol === 'https:') &&
           (parsed.host === hostport) &&
           (parsed.path === req.url);
  }
}

module.exports = TransportServer;
