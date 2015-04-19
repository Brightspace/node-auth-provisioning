'use strict';

var jwt = require('jsonwebtoken'),
	Promise = require('bluebird'),
	qs = require('querystringparser'),
	request = require('superagent');

var ASSERTION_AUDIENCE = 'https://api.brightspace.com/auth/token',
	ASSERTION_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer',
	ASSERTION_LIFETIME_SECONDS = 60,
	DEFAULT_REMOTE_ISSUER = 'https://auth.proddev.d2l:44331/core',
	TOKEN_PATH = '/connect/token';

function clock () {
	return Math.round(Date.now() / 1000);
}

function AuthTokenProvisioner (opts) {
	if (!(this instanceof AuthTokenProvisioner)) {
		return new AuthTokenProvisioner(opts);
	}

	opts = opts || {};

	if ('string' !== typeof opts.issuer || 0 === opts.issuer.length) {
		throw new Error('"opts.issuer" must be a valid string');
	}

	if ('function' !== typeof opts.keyLookup) {
		throw new Error('"opts.keyLookup" must be a function which returns a Promise to a signing key');
	}

	var remoteIssuer = 'string' === typeof opts.remoteIssuer
		? opts.remoteIssuer.replace(/\/+$/g, '')
		: DEFAULT_REMOTE_ISSUER;

	this._clock = clock;
	this._issuer = opts.issuer;
	this._latestKey = opts.keyLookup;
	this._tokenEndpoint = remoteIssuer + TOKEN_PATH;
}

AuthTokenProvisioner.prototype.provisionToken = Promise.method(function provisionToken (opts) {
	var self = this;

	opts = opts || {};

	if (!Array.isArray(opts.scopes)) {
		throw new Error('"opts.scopes" must be an array of strings');
	}

	var scope = opts.scopes.join(' ');

	var claims = {};
	if (opts.user) {
		if (!opts.tenant) {
			throw new Error('"opts.user" depends on "opts.tenant"');
		}

		claims.sub = opts.user;
	}
	if (opts.tenant) {
		claims.tenantid = opts.tenant;
	}

	return self
		._buildAssertion(claims)
		.then(function (assertion) {
			return self
				._makeAssertion(assertion, scope);
		});
});

AuthTokenProvisioner.prototype._buildAssertion = function buildAssertion (payload) {
	var self = this;

	return self
		._latestKey()
		.then(function (signingKey) {
			if ('object' !== typeof signingKey
				|| 'string' !== typeof signingKey.kid
				|| 'string' !== typeof signingKey.pem
			) {
				throw new Error('received invalid signing key from "keyLookup"');
			}

			payload.aud = ASSERTION_AUDIENCE;
			payload.iss = self._issuer;
			payload.iat = self._clock();
			payload.exp = payload.iat + ASSERTION_LIFETIME_SECONDS;

			var assertion = jwt.sign(payload, signingKey.pem, {
				header: {
					alg: 'RS256',
					kid: signingKey.kid
				},
				noTimestamp: true
			});

			return assertion;
		});
};

AuthTokenProvisioner.prototype._makeAssertion = function makeAssertion (assertion, scope) {
	var self = this;

	var body = qs.stringify({
		assertion: assertion,
		grant_type: ASSERTION_GRANT_TYPE,
		scope: scope
	});

	return new Promise(function (resolve, reject) {
		request
			.post(self._tokenEndpoint)
			.type('application/x-www-form-urlencoded')
			.send(body)
			.end(function (err, res) {
				if (err) {
					reject(err);
					return;
				}

				resolve(res.body.access_token);
			});
	});
};

module.exports = AuthTokenProvisioner;
