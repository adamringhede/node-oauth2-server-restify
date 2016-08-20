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

var validBody = {
  grantType: 'password',
  clientId: 'thom',
  clientSecret: 'nightworld',
  username: 'thomseddon',
  password: 'nightworld'
};

describe('Grant', function() {

  describe('when parsing request', function () {
    it('should only allow post', function (done) {
      var app = bootstrap();

      request(app)
        .get('/oauth/token')
        .expect(400, /method must be POST/i, done);
    });

    it('should only allow application/x-www-form-urlencoded', function (done) {
      var app = bootstrap();

      request(app)
        .post('/oauth/token')
        .set('Content-Type', 'application/json')
        .send({}) // Required to be valid JSON
        .expect(400, /application\/x-www-form-urlencoded/i, done);
    });

    it('should check grantType exists', function (done) {
      var app = bootstrap();

      request(app)
        .post('/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .expect(400, /invalid or missing grantType parameter/i, done);
    });

    it('should ensure grantType is allowed', function (done) {
      var app = bootstrap({ model: {}, grants: ['refreshToken'] });

      request(app)
        .post('/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send({ grantType: 'password' })
        .expect(400, /invalid or missing grantType parameter/i, done);
    });

    it('should check clientId exists', function (done) {
      var app = bootstrap();

      request(app)
        .post('/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send({ grantType: 'password' })
        .expect(400, /invalid or missing clientId parameter/i, done);
    });

    it('should check clientId matches regex', function (done) {
      var app = bootstrap({
        clientIdRegex: /match/,
        model: {},
        grants: ['password', 'refreshToken']
      });

      request(app)
        .post('/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send({ grantType: 'password', clientId: 'thom' })
        .expect(400, /invalid or missing clientId parameter/i, done);
    });

    it('should check clientSecret exists', function (done) {
      var app = bootstrap();

      request(app)
        .post('/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send({ grantType: 'password', clientId: 'thom' })
        .expect(400, /missing clientSecret parameter/i, done);
    });

    it('should extract credentials from body', function (done) {
      var app = bootstrap({
        model: {
          getClient: function (id, secret, callback) {
            id.should.equal('thom');
            secret.should.equal('nightworld');
            callback(false, false);
          }
        },
        grants: ['password']
      });

      request(app)
        .post('/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send({ grantType: 'password', clientId: 'thom', clientSecret: 'nightworld' })
        .expect(400, done);
    });

    it('should extract credentials from header (Basic)', function (done) {
      var app = bootstrap({
        model: {
          getClient: function (id, secret, callback) {
            id.should.equal('thom');
            secret.should.equal('nightworld');
            callback(false, false);
          }
        },
        grants: ['password']
      });

      request(app)
        .post('/oauth/token')
        .send('grantType=password&username=test&password=invalid')
        .set('Authorization', 'Basic dGhvbTpuaWdodHdvcmxk')
        .expect(400, done);
    });

    it('should detect unsupported grantType', function (done) {
      var app = bootstrap({
        model: {
          getClient: function (id, secret, callback) {
            callback(false, true);
          },
          grantTypeAllowed: function (clientId, grantType, callback) {
            callback(false, true);
          }
        },
        grants: ['refreshToken']
      });

      request(app)
        .post('/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send({ grantType: 'password', clientId: 'thom', clientSecret: 'nightworld' })
        .expect(400, /invalid or missing grantType/i, done);
    });
  });

  describe('check client credentials against model', function () {
    it('should detect invalid client', function (done) {
      var app = bootstrap({
        model: {
          getClient: function (id, secret, callback) {
            callback(false, false); // Fake invalid
          }
        },
        grants: ['password']
      });

      request(app)
        .post('/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send({ grantType: 'password', clientId: 'thom', clientSecret: 'nightworld' })
        .expect(400, /client credentials are invalid/i, done);
    });
  });

  describe('check grant type allowed for client (via model)', function () {
    it('should detect grant type not allowed', function (done) {
      var app = bootstrap({
        model: {
          getClient: function (id, secret, callback) {
            callback(false, true);
          },
          grantTypeAllowed: function (clientId, grantType, callback) {
            callback(false, false); // Not allowed
          }
        },
        grants: ['password']
      });

      request(app)
        .post('/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send({ grantType: 'password', clientId: 'thom', clientSecret: 'nightworld' })
        .expect(400, /grant type is unauthorised for this clientId/i, done);
    });
  });

  describe('generate access token', function () {
    it('should allow override via model', function (done) {
      var app = bootstrap({
        model: {
          getClient: function (id, secret, callback) {
            callback(false, true);
          },
          grantTypeAllowed: function (clientId, grantType, callback) {
            callback(false, true);
          },
          getUser: function (uname, pword, callback) {
            callback(false, { id: 1 });
          },
          generateToken: function (type, req, callback) {
            callback(false, 'thommy');
          },
          saveAccessToken: function (token, clientId, expires, user, cb) {
            token.should.equal('thommy');
            cb();
          }
        },
        grants: ['password']
      });

      request(app)
        .post('/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send(validBody)
        .expect(200, /thommy/, done);

    });

    it('should reissue if model returns object', function (done) {
      var app = bootstrap({
        model: {
          getClient: function (id, secret, callback) {
            callback(false, true);
          },
          grantTypeAllowed: function (clientId, grantType, callback) {
            callback(false, true);
          },
          getUser: function (uname, pword, callback) {
            callback(false, { id: 1 });
          },
          generateToken: function (type, req, callback) {
            callback(false, { accessToken: 'thommy' });
          },
          saveAccessToken: function (token, clientId, expires, user, cb) {
            cb(new Error('Should not be saving'));
          }
        },
        grants: ['password']
      });

      request(app)
        .post('/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send(validBody)
        .expect(200, /"accessToken":"thommy"/, done);

    });
  });

  describe('saving access token', function () {
    it('should pass valid params to model.saveAccessToken', function (done) {
      var app = bootstrap({
        model: {
          getClient: function (id, secret, callback) {
            callback(false, { clientId: 'thom' });
          },
          grantTypeAllowed: function (clientId, grantType, callback) {
            callback(false, true);
          },
          getUser: function (uname, pword, callback) {
            callback(false, { id: 1 });
          },
          saveAccessToken: function (token, clientId, expires, user, cb) {
            token.should.be.instanceOf(String);
            token.should.have.length(40);
            clientId.should.equal('thom');
            user.id.should.equal(1);
            (+expires).should.be.within(10, (+new Date()) + 3600000);
            cb();
          }
        },
        grants: ['password']
      });

      request(app)
        .post('/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send(validBody)
        .expect(200, done);

    });

    it('should pass valid params to model.saveRefreshToken', function (done) {
      var app = bootstrap({
        model: {
          getClient: function (id, secret, callback) {
            callback(false, { clientId: 'thom' });
          },
          grantTypeAllowed: function (clientId, grantType, callback) {
            callback(false, true);
          },
          getUser: function (uname, pword, callback) {
            callback(false, { id: 1 });
          },
          saveAccessToken: function (token, clientId, expires, user, cb) {
            cb();
          },
          saveRefreshToken: function (token, clientId, expires, user, cb) {
            token.should.be.instanceOf(String);
            token.should.have.length(40);
            clientId.should.equal('thom');
            user.id.should.equal(1);
            (+expires).should.be.within(10, (+new Date()) + 1209600000);
            cb();
          }
        },
        grants: ['password', 'refreshToken']
      });

      request(app)
        .post('/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send(validBody)
        .expect(200, done);

    });
  });

  describe('issue access token', function () {
    it('should return an oauth compatible response', function (done) {
      var app = bootstrap({
        model: {
          getClient: function (id, secret, callback) {
            callback(false, { clientId: 'thom' });
          },
          grantTypeAllowed: function (clientId, grantType, callback) {
            callback(false, true);
          },
          getUser: function (uname, pword, callback) {
            callback(false, { id: 1 });
          },
          saveAccessToken: function (token, clientId, expires, user, cb) {
            cb();
          }
        },
        grants: ['password']
      });

      request(app)
        .post('/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send(validBody)
        .expect(200)
        .end(function (err, res) {
          if (err) return done(err);

          res.body.should.have.keys(['accessToken', 'tokenType', 'expires_in']);
          res.body.accessToken.should.be.instanceOf(String);
          res.body.accessToken.should.have.length(40);
          res.body.tokenType.should.equal('bearer');
          res.body.expires_in.should.equal(3600);

          done();
        });

    });

    it('should return an oauth compatible response with refreshToken', function (done) {
      var app = bootstrap({
        model: {
          getClient: function (id, secret, callback) {
            callback(false, { clientId: 'thom' });
          },
          grantTypeAllowed: function (clientId, grantType, callback) {
            callback(false, true);
          },
          getUser: function (uname, pword, callback) {
            callback(false, { id: 1 });
          },
          saveAccessToken: function (token, clientId, expires, user, cb) {
            cb();
          },
          saveRefreshToken: function (token, clientId, expires, user, cb) {
            cb();
          }
        },
        grants: ['password', 'refreshToken']
      });

      request(app)
        .post('/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send(validBody)
        .expect(200)
        .end(function (err, res) {
          if (err) return done(err);

          res.body.should.have.keys(['accessToken', 'tokenType', 'expires_in',
            'refreshToken']);
          res.body.accessToken.should.be.instanceOf(String);
          res.body.accessToken.should.have.length(40);
          res.body.refreshToken.should.be.instanceOf(String);
          res.body.refreshToken.should.have.length(40);
          res.body.tokenType.should.equal('bearer');
          res.body.expires_in.should.equal(3600);

          done();
        });

    });

    it('should exclude expires_in if accessTokenLifetime = null', function (done) {
      var app = bootstrap({
        model: {
          getClient: function (id, secret, callback) {
            callback(false, { clientId: 'thom' });
          },
          grantTypeAllowed: function (clientId, grantType, callback) {
            callback(false, true);
          },
          getUser: function (uname, pword, callback) {
            callback(false, { id: 1 });
          },
          saveAccessToken: function (token, clientId, expires, user, cb) {
            should.strictEqual(null, expires);
            cb();
          },
          saveRefreshToken: function (token, clientId, expires, user, cb) {
            should.strictEqual(null, expires);
            cb();
          }
        },
        grants: ['password', 'refreshToken'],
        accessTokenLifetime: null,
        refreshTokenLifetime: null
      });

      request(app)
        .post('/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send(validBody)
        .expect(200)
        .end(function (err, res) {
          if (err) return done(err);

          res.body.should.have.keys(['accessToken', 'refreshToken', 'tokenType']);
          res.body.accessToken.should.be.instanceOf(String);
          res.body.accessToken.should.have.length(40);
          res.body.refreshToken.should.be.instanceOf(String);
          res.body.refreshToken.should.have.length(40);
          res.body.tokenType.should.equal('bearer');

          done();
        });

    });

    it('should continue after success response if continueAfterResponse1 = true', function (done) {
      var app = bootstrap({
        model: {
          getClient: function (id, secret, callback) {
            callback(false, { clientId: 'thom' });
          },
          grantTypeAllowed: function (clientId, grantType, callback) {
            callback(false, true);
          },
          getUser: function (uname, pword, callback) {
            callback(false, { id: 1 });
          },
          saveAccessToken: function (token, clientId, expires, user, cb) {
            cb();
          }
        },
        grants: ['password'],
        continueAfterResponse: true
      });

      var hit = false;
      app.all('*', function (req, res, done) {
        hit = true;
      });

      request(app)
        .post('/oauth/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send(validBody)
        .expect(200)
        .end(function (err, res) {
          if (err) return done(err);
          hit.should.equal(true);
          done();
        });
    });

  });

});
