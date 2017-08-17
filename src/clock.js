'use strict';

module.exports = function clock() {
	return Math.round(Date.now() / 1000);
};
