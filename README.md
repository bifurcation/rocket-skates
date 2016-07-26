rocket-skates
=============

Reference implementation of [ACME](https://ietf-wg-acme.github.io/acme/).

[![Build Status](https://travis-ci.org/hildjj/node-acme.svg?branch=master)](https://travis-ci.org/hildjj/node-acme)
[![Coverage Status](https://coveralls.io/repos/hildjj/node-acme/badge.svg?branch=master&service=github)](https://coveralls.io/github/hildjj/node-acme?branch=master)

![Wile E. Coyote on rocket skates](https://ipv.sx/rocket-skates/rocket-skates.png)


## Goals

This implementation is intended more as a tool for learning about ACME and
working on its development than something to be used in production.

* Demonstrate how the protocol works in as minimal as a way as possible
* Provide a platform to show how possible changes to the protocol impact an
  implementation
* Provide a testing / conformance tool for people developing ACME
  implementations
* 100% test and documentation coverage
* Non-goal: Having a clean command line interface or API


## Architecture

Internally, this module has a layered structure reflecting the layering of ACME.

* `jose` and `nonce-source` modules that provide some basic services
* `transport-client` and `transport-server` address the [transport layer
  requirements](https://ietf-wg-acme.github.io/acme/#rfc.section.5) of the
  protocol, e.g., message signing and verification.
* `acme-client` and `acme-server` provide the logic for the [application-level
  issuance flow](https://ietf-wg-acme.github.io/acme/#rfc.section.6)
* For each [challenge type](https://ietf-wg-acme.github.io/acme/#rfc.section.7),
  there is a `-validation` module that provides the client-side logic and a
  `-challenge` module for the server-side logic

The idea is that you can when you instantiate a server, you provide it with the
challenge modules that you want it to offer, and likewise with the client and
the validation modules you want it to support.

```
 acme-server             acme-client           |   http-validation
      |                       |                |   dns-validation
      |                       +------------+   |   tls-sni-validation
      |                       |            |   |
transport-server        transport-client  pki  |   http-challenge
      |   |                   |                |   dns-challenge
      |   +--------+----------+                |   tls-sni-challenge
      |            |
 nonce-source     jose
```

You can also define your own challenge / validation modules by following the
interface used by the current set (in pseudo-JS):

```
interface Validation {
  // key        = A 'node-jose' key object
  // challenge  = An ACME challenge (not a challenge as below)
  // return     - Promise that resolves to an ACME response
  static makeResponse(key, challenge);

  // name       = The domain name being validated
  // challenge  = An ACME challenge
  // response   = The corresponding ACME response
  // onready    = A callback called with no arguments when the validation
  //              server is ready for the ACME server (mainly for testing)
  // return     - Promise that resolves when the validation request has been
  //              received and the server shut down.
  static respond(name, challenge, response, readyCallback);
}

interface Challenge {
  // name       = The domain name being validated
  // thumbprint = The thumbprint of the client's account key
  // return     - A new challenge object
  constructor(name, thumbprint);

  // response   = An ACME response
  // return     - A promise that resolves if the challenge was successful and
  //              rejects if it failed for any reason
  update(response);

  // return     - The JSON (ACME) form of the challenge
  toJSON();
}
```

