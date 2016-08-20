/**
 * Copyright 2013-present NightWorld.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var express = require('express'),
  bodyParser = require('body-parser'),
  request = require('supertest'),
  should = require('should');

var oauth2server = require('../');

var bootstrap = function (oauthConfig) {
  var app = express(),
    oauth = oauth2server(oauthConfig || {
      model: {},
      grants: ['password', 'refreshToken']
    });

  app.set('json spaces', 0);
  app.use(bodyParser());

  app.all('/oauth/token', oauth.grant());

  app.use(oauth.errorHandler());

  return app;
};

describe('Granting with authorizationCode grant type', function () {
  it('should detect missing parameters', function (done) {
    var app = bootstrap({
      model: {
        getClient: function (id, secret, callback) {
          callback(false, true);
        },
        grantTypeAllowed: function (clientId, grantType, callback) {
          callback(false, true);
        }
      },
      grants: ['authorizationCode']
    });

    request(app)
      .post('/oauth/token')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send({
        grantType: 'authorizationCode',
        clientId: 'thom',
        clientSecret: 'nightworld'
      })
      .expect(400, /no \\"code\\" parameter/i, done);

  });

  it('should invalid authorizationCode', function (done) {
    var app = bootstrap({
      model: {
        getClient: function (id, secret, callback) {
          callback(false, true);
        },
        grantTypeAllowed: function (clientId, grantType, callback) {
          callback(false, true);
        },
        getAuthCode: function (code, callback) {
          callback(false); // Fake invalid
        }
      },
      grants: ['authorizationCode']
    });

    request(app)
      .post('/oauth/token')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send({
        grantType: 'authorizationCode',
        clientId: 'thom',
        clientSecret: 'nightworld',
        code: 'abc123'
      })
      .expect(400, /invalid code/i, done);
  });

  it('should detect invalid clientId', function (done) {
    var app = bootstrap({
      model: {
        getClient: function (id, secret, callback) {
          callback(false, true);
        },
        grantTypeAllowed: function (clientId, grantType, callback) {
          callback(false, true);
        },
        getAuthCode: function (code, callback) {
          callback(false, { clientId: 'wrong' });
        }
      },
      grants: ['authorizationCode']
    });

    request(app)
      .post('/oauth/token')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send({
        grantType: 'authorizationCode',
        clientId: 'thom',
        clientSecret: 'nightworld',
        code: 'abc123'
      })
      .expect(400, /invalid code/i, done);
  });

  it('should detect expired code', function (done) {
    var app = bootstrap({
      model: {
        getClient: function (id, secret, callback) {
          callback(false, { clientId: 'thom' });
        },
        grantTypeAllowed: function (clientId, grantType, callback) {
          callback(false, true);
        },
        getAuthCode: function (data, callback) {
          callback(false, {
            clientId: 'thom',
            expires: new Date(+new Date() - 60)
          });
        }
      },
      grants: ['authorizationCode']
    });

    request(app)
      .post('/oauth/token')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send({
        grantType: 'authorizationCode',
        clientId: 'thom',
        clientSecret: 'nightworld',
        code: 'abc123'
      })
      .expect(400, /code has expired/i, done);
  });

  it('should require code expiration', function (done) {
    var app = bootstrap({
      model: {
        getClient: function (id, secret, callback) {
          callback(false, { clientId: 'thom' });
        },
        grantTypeAllowed: function (clientId, grantType, callback) {
          callback(false, true);
        },
        getAuthCode: function (data, callback) {
          callback(false, {
            clientId: 'thom',
            expires: null // This is invalid
          });
        }
      },
      grants: ['authorizationCode']
    });

    request(app)
      .post('/oauth/token')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send({
        grantType: 'authorizationCode',
        clientId: 'thom',
        clientSecret: 'nightworld',
        code: 'abc123'
      })
      .expect(400, /code has expired/i, done);
  });


  it('should allow valid request', function (done) {
    var app = bootstrap({
      model: {
        getClient: function (id, secret, callback) {
          callback(false, { clientId: 'thom' });
        },
        grantTypeAllowed: function (clientId, grantType, callback) {
          callback(false, true);
        },
        getAuthCode: function (refreshToken, callback) {
          refreshToken.should.equal('abc123');
          callback(false, {
            clientId: 'thom',
            expires: new Date(),
            userId: '123'
          });
        },
        saveAccessToken: function (token, clientId, expires, user, cb) {
          cb();
        },
        saveRefreshToken: function (data, cb) {
          cb();
        },
        expireRefreshToken: function (refreshToken, callback) {
          callback();
        }
      },
      grants: ['authorizationCode']
    });

    request(app)
      .post('/oauth/token')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send({
        grantType: 'authorizationCode',
        clientId: 'thom',
        clientSecret: 'nightworld',
        code: 'abc123'
      })
      .expect(200, /"accessToken":"(.*)"/i, done);
  });

});
