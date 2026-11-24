const _ = require('lodash'); const jwt = require('jsonwebtoken'); const axios = require('axios');
function render(el, q) { el.innerHTML = q; }
function auth(t) { return jwt.verify(t, key, { algorithms: ['none'] }); }
