'use strict';

var jws = require('jws'),
	promised = require('promised-method'),
	qs = require('querystring'),
	request = require('superagent'),
	uuid = require('uuid/v4'),
	xtend = require('xtend');

var AbstractProvisioningCache = require('./abstract-provisioning-cache'),
	clock = require('./clock');

var ASSERTION_AUDIENCE = 'https://api.brightspace.com/auth/token',
	ASSERTION_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer',
	ASSERTION_LIFETIME_SECONDS = 60,
	DEFAULT_REMOTE_ISSUER = 'https://auth.brightspace.com/core',
	TOKEN_PATH = '/connect/token',
	SUPPORTED_ALGS = ['ES256', 'ES384', 'ES512', 'RS256'/*, 'RS384', 'RS512'*/]; // D2L.Security.OAuth2 assumes RS256

function AuthTokenProvisioner(opts) {
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

	this._cache = opts.cache || new AbstractProvisioningCache();

	if (!(this._cache instanceof AbstractProvisioningCache)) {
		throw new Error('"opts.cache" must be an instance of AbstractProvisioningCache if provided');
	}

	var remoteIssuer = 'string' === typeof opts.remoteIssuer
		? opts.remoteIssuer.replace(/\/+$/g, '')
		: DEFAULT_REMOTE_ISSUER;

	this._clock = clock;
	this._issuer = opts.issuer;
	this._latestKey = opts.keyLookup;
	this._tokenEndpoint = remoteIssuer + TOKEN_PATH;
}

AuthTokenProvisioner.prototype.provisionToken = promised(/* @this */ function provisionToken(opts) {
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
	if (opts.impersonator) {
		if (!claims.sub) {
			throw new Error('"opts.impersonator" depends on "opts.user"');
		}

		claims.actualsub = opts.impersonator;
	}

	if (opts.fsid) {
		claims.fsid = opts.fsid;
	}

	return self
		._cache
		.get(claims, scope)
		.catch(function() {
			return self
				._buildAssertion(claims)
				.then(function(assertion) {
					return self
						._makeAssertion(assertion, scope);
				})
				.then(function(token) {
					return self
						._cache
						.set(claims, scope, token)
						.catch(function() {})
						.then(function() {
							return token;
						});
				});
		});
});

AuthTokenProvisioner.prototype._buildAssertion = function buildAssertion(payload) {
	var self = this;

	return self
		._latestKey()
		.then(function(signingKey) {
			if ('object' !== typeof signingKey
				|| 'string' !== typeof signingKey.kid
				|| 'string' !== typeof signingKey.pem
			) {
				throw new Error('received invalid signing key from "keyLookup"');
			}

			if ('undefined' !== typeof signingKey.alg
				&& -1 === SUPPORTED_ALGS.indexOf(signingKey.alg)
			) {
				throw new Error('received invalid signing key from "keyLookup"');
			}

			payload = xtend(payload);

			payload.aud = ASSERTION_AUDIENCE;
			payload.iss = self._issuer;
			payload.iat = payload.nbf = self._clock();
			payload.exp = payload.iat + ASSERTION_LIFETIME_SECONDS;

			var assertion = jws.sign({
				header: {
					alg: signingKey.alg || 'RS256',
					kid: signingKey.kid,
					typ: 'JWT',
					jti: uuid()
				},
				payload: JSON.stringify(payload),
				secret: signingKey.pem,
				encoding: 'utf8'
			});

			return assertion;
		});
};

AuthTokenProvisioner.prototype._makeAssertion = function makeAssertion(assertion, scope) {
	var self = this;

	var body = qs.stringify({
		assertion: assertion,
		grant_type: ASSERTION_GRANT_TYPE,
		scope: scope
	});

	return new Promise(function(resolve, reject) {
		request
			.post(self._tokenEndpoint)
			.type('application/x-www-form-urlencoded')
			.send(body)
			.end(function(err, res) {
				if (err) {
					reject(err);
					return;
				}

				resolve(res.body.access_token);
			});
	});
};

module.exports = AuthTokenProvisioner;
module.exports.AbstractProvisioningCache = AbstractProvisioningCache;
