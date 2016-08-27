// Copyright (c) 2016 the rocket-skates AUTHORS.  All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert            = require('chai').assert;
const rp                = require('request-promise');
const Promise           = require('bluebird');
const PageViewChallenge = require('../lib/server/page-view-challenge.js');

PageViewChallenge.port = 8888;

describe('page-view (oob-01) challenge', () => {
  it('updates and accepts a query', (done) => {
    let challenge = new PageViewChallenge();
    assert.equal(challenge.status, 'pending');
    assert.property(challenge.toJSON(), 'href');

    let response = {type: PageViewChallenge.type};
    rp.get(challenge.href)
      .then(() => { challenge.update(response); })
      .then(() => {
        assert.equal(challenge.status, 'valid');
        assert.property(challenge.toJSON(), 'validated');
        done();
      })
      .catch(done);
  });

  it('rejects a response with the wrong type', (done) => {
    let challenge = new PageViewChallenge();
    let response = {type: 'not-oob'};

    challenge.update(response)
      .then(() => {
        assert.equal(challenge.status, 'invalid');
        done();
      })
      .catch(done);
  });

  it('times out', (done) => {
    let originalTimeout = PageViewChallenge.timeout;
    PageViewChallenge.timeout = 20;

    let challenge = new PageViewChallenge();

    Promise.delay(2 * PageViewChallenge.timeout)
      .then(() => {
        PageViewChallenge.timeout = originalTimeout;
        assert.equal(challenge.status, 'invalid');
        done();
      })
      .catch(err => {
        PageViewChallenge.timeout = originalTimeout;
        done(err);
      });
  });
});
