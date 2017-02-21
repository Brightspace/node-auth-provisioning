# brightspace-auth-provisioning

[![Build Status](https://travis-ci.org/Brightspace/node-auth-provisioning.svg?branch=master)](https://travis-ci.org/Brightspace/node-auth-provisioning)

Library for making assertions against an auth service.

## Install

```bash
npm install brightspace-auth-provisioning --save
```


## Usage

```js
var AuthTokenProvisioner = require('brightspace-auth-provisioning');

var provisioner = new AuthTokenProvisioner({
	issuer: 'ece083bc-e6ac-11e4-8e1b-54ee750fffa4',
	keyLookup: function () {
		return Promise.resolve({
			kid: '0a9e68f6-e6ad-11e4-8ab6-54ee750fffa4',
			pem: '...',
			alg: 'ES256'
		});
	}
});

var tokenPromise = provisioner
	.provisionToken({
		user: '32647',
		impersonator: '30882',
		tenant: '5492ff8a-e6ad-11e4-84d6-54ee750fffa4',
		scopes: ['updates:feed-items:read'],
		fsid: 'eyJhbGciOiJIUzI1Ni...'
	});
```

### API

---

#### `new AuthTokenProvisioner(Object options)` -> `AuthTokenProvisioner`


##### Option: issuer `String` _(required)_

The `String` used to identify your local issuer/service. This must be registered
with the auth service.

##### Option: keyLookup `()` -> `Promise<Object>` _(required)_

A function which returns a `Promise` to an `Object` representing your current
signing key. The object must have the properties `kid`, which is a unique
`String`, and `pem` which is the `String` representing the private key. The
object should also have a `String` property `alg` representing the signing
algorithm to use. `alg` must be one of `ES256`, `ES384`, `ES512` or `RS256`.
`RS256` will be assumed if `alg` is not provided.

**NOTE:** `alg` will be required in the future.

##### Option: remoteIssuer `String` _(https://auth.brightspace.com/core)_

You may optionally specifiy the endpoint of the remote issuer, or auth service.

##### Option: cache `AbstractProvisioningCache` _(AbstractProvisioningCache)_

You may optionally specify an instance of an object inheriting from
`AuthTokenProvisioner.AbstractProvisioningCache`.

---

#### `.provisionToken(Object options)` -> `Promise<String>`

Given the set of claims provided, will make an assertion against the auth
service. Returns a promise to the encoded access token.

##### Option: scopes `Array<String>` _(required)_

The set of scopes to include in the auth token. The contained scopes _should_
fit our semantic scope formatting: `<group>:<resource>:<permission>`.

##### Option: tenant `String`

The GUID of the tenant this token is meant for.

##### Option: user `String`

The id of the user this token is meant for. Requires the _tenant_ option has
been set.

##### Option: impersonator `String`

The id of the active user, who is impersonating _user_. Requires the _user_
option has been set.

##### Option: fsid `String`

The Caliper FSID associated with this token.

---

#### `.AbstractProvisioningCache`

Available on the export is a reference to the `AbstractProvisioningCache`

## Testing

```bash
npm test
```

## Contributing

1. **Fork** the repository. Committing directly against this repository is
   highly discouraged.

2. Make your modifications in a branch, updating and writing new unit tests
   as necessary in the `spec` directory.

3. Ensure that all tests pass with `npm test`

4. `rebase` your changes against master. *Do not merge*.

5. Submit a pull request to this repository. Wait for tests to run and someone
   to chime in.

### Code Style

This repository is configured with [EditorConfig][EditorConfig] and
[ESLint][ESLint] rules.

[EditorConfig]: http://editorconfig.org/
[ESLint]: http://eslint.org
