'use strict';

var inherits = require('util').inherits,
	jws = require('jws'),
	promised = require('promised-method'),
	qs = require('querystring'),
	xtend = require('xtend');

var clock = require('./clock');

var DEFAULT_EXPIRY_SECONDS = 60 * 60,
	EXPIRY_BUFFER_TIME_SECONDS = 2 * 60;

function ValueLookupFailed(inner) {
	this.name = 'ValueLookupFailed';
	this.message = 'Value lookup failed';
	this.inner = inner;
}
inherits(ValueLookupFailed, Error);

function noop() {}

function AbstractProvisioningCache() {}

AbstractProvisioningCache.prototype.get = promised(/* @this */ function get(claims, scope) {
	if ('object' !== typeof claims) {
		throw new Error('"claims" must be an Object');
	}

	if ('string' !== typeof scope) {
		throw new Error('"scope" must be a String');
	}

	if ('function' !== typeof this._get) {
		throw new ValueLookupFailed();
	}

	var key = this._buildKey(claims, scope);

	return Promise
		.resolve(this._get(key))
		.catch(function(err) {
			err = new ValueLookupFailed(err);
			throw err;
		})
		.then(function(token) {
			if ('string' !== typeof token) {
				throw new ValueLookupFailed();
			}

			var decodedToken = jws.decode(token);

			if ('object' !== typeof decodedToken
				|| 'object' !== typeof decodedToken.payload
				|| 'number' !== typeof decodedToken.payload.exp
				|| (decodedToken.payload.exp - EXPIRY_BUFFER_TIME_SECONDS) <= clock()
			) {
				throw new ValueLookupFailed();
			}

			return token;
		});
});

AbstractProvisioningCache.prototype.set = promised(/* @this */ function set(claims, scope, token) {
	if ('object' !== typeof claims) {
		throw new Error('"claims" must be an Object');
	}

	if ('string' !== typeof scope) {
		throw new Error('"scope" must be a String');
	}

	if ('string' !== typeof token) {
		throw new Error('"token" must be an encoded jwt');
	}

	var decodedToken = jws.decode(token);
	if ('object' !== typeof decodedToken || 'object' !== typeof decodedToken.payload) {
		throw new Error('"token" must be an encoded jwt');
	}

	if ('function' !== typeof this._set) {
		return;
	}

	var key = this._buildKey(claims, scope);

	var expiry = 'number' === typeof decodedToken.payload.exp
		? decodedToken.payload.exp
		: DEFAULT_EXPIRY_SECONDS + clock();
	expiry -= EXPIRY_BUFFER_TIME_SECONDS;

	return Promise
		.resolve(this._set(key, token, expiry))
		.then(noop);
});

AbstractProvisioningCache.prototype._buildKey = function buildKey(claims, scope) {
	var request = xtend(claims);
	request.scope = scope;

	return qs.stringify(request);
};

module.exports = AbstractProvisioningCache;
