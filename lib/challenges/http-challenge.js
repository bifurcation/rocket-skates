'use strict';

const crypto = require('crypto');
const rp     = require('request-promise');

class HTTP01Challenge {
  constructor(name, thumbprint) {
    this.status = 'pending';
    this.name = name;

    this.token = crypto.randomBytes(32).toString('base64')
                       .replace(/\//g, '_').replace(/\+/g, '-')
                       .replace(/=/g, '');
    this._keyAuthorization = this.token + '.' + thumbprint;
  }

  update(response) {
    if (!response.type || (response.type !== HTTP01Challenge.type) ||
        !response.keyAuthorization ||
        (response.keyAuthorization !== this._keyAuthorization)) {
      this.status = 'invalid';
      return Promise.resolve(this);
    }

    this.keyAuthorization = this._keyAuthorization;

    let url = `http://${this.name}/.well-known/acme-challenge/${this.token}`;
    return rp.get(url)
      .then(body => {
        body = body.replace(/\s*$/, '');
        if (body === this._keyAuthorization) {
          this.status = 'valid';
        } else {
          this.status = 'invalid';
        }
      })
      .catch(() => {
        this.status = 'invalid';
      });
  }

  toJSON() {
    let obj = {
      type:             HTTP01Challenge.type,
      status:           this.status,
      token:            this.token
    };

    if (this.keyAuthorization) {
      obj.keyAuthorization = this.keyAuthorization;
    }

    return obj;
  }
}

HTTP01Challenge.type = 'http-01';

module.exports = HTTP01Challenge;
