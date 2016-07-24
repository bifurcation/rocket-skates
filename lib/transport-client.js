// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const jose        = require('./jose');
const rp          = require('request-promise');
const parseLink   = require('parse-link-header');
const Promise     = require('bluebird');

const DEFAULT_POLL_LIMIT = 4;
const DEFAULT_POLL_DELAY = 500;

class Response {
  constructor(response) {
    this.response = response;
  }

  get location() {
    return this.response.headers['location'];
  }

  get links() {
    if (this._links) {
      return this._links;
    }

    let link = this.response.headers['link'];
    if (!link) {
      return {};
    }
    this._links = parseLink(link);
    return this._links;
  }

  get body() {
    return this.response.body;
  }
}

class TransportClient {
  constructor(options) {
    if (!options.accountKey) {
      throw new TypeError('Account key required');
    }

    this.accountKey = options.accountKey;
    this.nonces = [];
  }

  static get(url, binary) {
    let options = {
      uri:                     url,
      resolveWithFullResponse: true
    };

    if (binary) {
      options.encoding = null;
    } else {
      options.json = true;
    }

    return rp.get(options)
      .then(response => {
        return new Response(response);
      });
  }

  static poll(url, test, limit, delay) {
    if (limit <= 0) {
      throw new Error('Polling limit exceeded');
    }

    limit = limit || DEFAULT_POLL_LIMIT;
    delay = delay || DEFAULT_POLL_DELAY;

    return this.get(url)
      .then(obj => {
        let res = new Response(obj);
        if (test(res)) {
          return res;
        }

        return Promise.delay(delay)
          .then(() => this.poll(url, test, limit - 1, delay));
      });
  }

  _nonce(url) {
    let nonce = this.nonces.shift();

    if (nonce) {
      return Promise.resolve(nonce);
    }

    return rp.head({
      uri:                     url,
      json:                    true,
      resolveWithFullResponse: true,
      simple:                  false
    }).then(resp => {
      if (resp.headers['replay-nonce']) {
        return resp.headers['replay-nonce'];
      }
      throw new Error('No nonce available');
    });
  }

  post(url, body) {
    return this._nonce(url)
      .then(nonce => {
        let header = {
          nonce: nonce,
          url:   url
        };
        return jose.sign(this.accountKey, body, header);
      })
      .then(jws => {
        return rp.post({
          uri:                     url,
          resolveWithFullResponse: true,
          json:                    true,
          body:                    jws
        });
      })
      .then(resp => {
        if (resp.headers['replay-nonce']) {
          this.nonces.push(resp.headers['replay-nonce']);
        }
        return new Response(resp);
      });
  }
}

module.exports = TransportClient;
