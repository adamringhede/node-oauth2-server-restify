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

var pg = require('pg'),
  model = module.exports,
  connString = process.env.DATABASE_URL;

/*
 * Required
 */

model.getAccessToken = function (bearerToken, callback) {
  pg.connect(connString, function (err, client, done) {
    if (err) return callback(err);
    client.query('SELECT accessToken, clientId, expires, userId FROM oauth_accessTokens ' +
        'WHERE accessToken = $1', [bearerToken], function (err, result) {
      if (err || !result.rowCount) return callback(err);
      // This object will be exposed in req.oauth.token
      // The userId field will be exposed in req.user (req.user = { id: "..." }) however if
      // an explicit user object is included (token.user, must include id) it will be exposed
      // in req.user instead
      var token = result.rows[0];
      callback(null, {
        accessToken: token.accessToken,
        clientId: token.clientId,
        expires: token.expires,
        userId: token.userId
      });
      done();
    });
  });
};

model.getClient = function (clientId, clientSecret, callback) {
  pg.connect(connString, function (err, client, done) {
    if (err) return callback(err);

    client.query('SELECT clientId, clientSecret, redirect_uri FROM oauthClients WHERE ' +
      'clientId = $1', [clientId], function (err, result) {
      if (err || !result.rowCount) return callback(err);

      var client = result.rows[0];

      if (clientSecret !== null && client.clientSecret !== clientSecret) return callback();

      // This object will be exposed in req.oauth.client
      callback(null, {
        clientId: client.clientId,
        clientSecret: client.clientSecret
      });
      done();
    });
  });
};

model.getRefreshToken = function (bearerToken, callback) {
  pg.connect(connString, function (err, client, done) {
    if (err) return callback(err);
    client.query('SELECT refreshToken, clientId, expires, userId FROM oauth_refreshTokens ' +
        'WHERE refreshToken = $1', [bearerToken], function (err, result) {
      // The returned userId will be exposed in req.user.id
      callback(err, result.rowCount ? result.rows[0] : false);
      done();
    });
  });
};

// This will very much depend on your setup, I wouldn't advise doing anything exactly like this but
// it gives an example of how to use the method to resrict certain grant types
var authorizedClientIds = ['abc1', 'def2'];
model.grantTypeAllowed = function (clientId, grantType, callback) {
  if (grantType === 'password') {
    return callback(false, authorizedClientIds.indexOf(clientId.toLowerCase()) >= 0);
  }

  callback(false, true);
};

model.saveAccessToken = function (accessToken, clientId, expires, userId, callback) {
  pg.connect(connString, function (err, client, done) {
    if (err) return callback(err);
    client.query('INSERT INTO oauth_accessTokens(accessToken, clientId, userId, expires) ' +
        'VALUES ($1, $2, $3, $4)', [accessToken, clientId, userId, expires],
        function (err, result) {
      callback(err);
      done();
    });
  });
};

model.saveRefreshToken = function (refreshToken, clientId, expires, userId, callback) {
  pg.connect(connString, function (err, client, done) {
    if (err) return callback(err);
    client.query('INSERT INTO oauth_refreshTokens(refreshToken, clientId, userId, ' +
        'expires) VALUES ($1, $2, $3, $4)', [refreshToken, clientId, userId, expires],
        function (err, result) {
      callback(err);
      done();
    });
  });
};

/*
 * Required to support password grant type
 */
model.getUser = function (username, password, callback) {
  pg.connect(connString, function (err, client, done) {
    if (err) return callback(err);
    client.query('SELECT id FROM users WHERE username = $1 AND password = $2', [username,
        password], function (err, result) {
      callback(err, result.rowCount ? result.rows[0] : false);
      done();
    });
  });
};
