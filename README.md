# brightspace-auth-provisioning

Library for making assertions against an auth service.

## Install

```bash
npm install @d2l/brightspace-auth-provisioning --save
```


## Usage

```js
var AuthTokenProvisioner = require('@d2l/brightspace-auth-provisioning');

var provisioner = new AuthTokenProvisioner({
	issuer: 'ece083bc-e6ac-11e4-8e1b-54ee750fffa4',
	keyLookup: function () {
		return Promise.resolve({
			kid: '0a9e68f6-e6ad-11e4-8ab6-54ee750fffa4',
			pem: '...'
		});
	}
});

var tokenPromise = provisioner
	.provisionToken({
		user: '32647',
		tenant: '5492ff8a-e6ad-11e4-84d6-54ee750fffa4',
		scopes: ['updates:feed-items:read']
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
`String`, and `pem` which is the `String` representing the private key.

**NOTE:** Only _RSA_ keys are supported at this time.

##### Option: remoteIssuer `String` _(https://auth.proddev.d2l:44331/core)_

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

This repository is configured with [EditorConfig][EditorConfig], [jscs][jscs]
and [JSHint][JSHint] rules. See the [docs.dev code style article][code style]
for information on installing editor extensions.

[EditorConfig]: http://editorconfig.org/
[jscs]: http://jscs.info/
[JSHint]: http://jshint.com/
[code style]: http://docs.dev.d2l/index.php/JavaScript_Code_Style_(Personal_Learning)
