var express = require('express'),
  bodyParser = require('body-parser'),
  oauthserver = require('../../'); // Would be: 'oauth2-server'

var app = express();

app.use(bodyParser());

app.oauth = oauthserver({
  model: require('./model'),
  grants: ['password', 'refreshToken'],
  debug: true
});

// Handle token grant requests
app.all('/oauth/token', app.oauth.grant());

// Show them the "do you authorise xyz app to access your content?" page
app.get('/oauth/authorise', function (req, res, next) {
  if (!req.session.user) {
    // If they aren't logged in, send them to your own login implementation
    return res.redirect('/login?redirect=' + req.path + '&clientId=' +
        req.query.clientId + '&redirect_uri=' + req.query.redirect_uri);
  }

  res.render('authorise', {
    clientId: req.query.clientId,
    redirect_uri: req.query.redirect_uri
  });
});

// Handle authorise
app.post('/oauth/authorise', function (req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login?clientId=' + req.query.clientId +
      '&redirect_uri=' + req.query.redirect_uri);
  }

  next();
}, app.oauth.authCodeGrant(function (req, next) {
  // The first param should to indicate an error
  // The second param should a bool to indicate if the user did authorise the app
  // The third param should for the user/uid (only used for passing to saveAuthCode)
  next(null, req.body.allow === 'yes', req.session.user.id, req.session.user);
}));

// Show login
app.get('/login', function (req, res, next) {
  res.render('login', {
    redirect: req.query.redirect,
    clientId: req.query.clientId,
    redirect_uri: req.query.redirect_uri
  });
});

// Handle login
app.post('/login', function (req, res, next) {
  // Insert your own login mechanism
  if (req.body.email !== 'thom@nightworld.com') {
    res.render('login', {
      redirect: req.body.redirect,
      clientId: req.body.clientId,
      redirect_uri: req.body.redirect_uri
    });
  } else {
    // Successful logins should send the user back to the /oauth/authorise
    // with the clientId and redirect_uri (you could store these in the session)
    return res.redirect((req.body.redirect || '/home') + '?clientId=' +
        req.body.clientId + '&redirect_uri=' + req.body.redirect_uri);
  }
});

app.get('/secret', app.oauth.authorise(), function (req, res) {
  // Will require a valid accessToken
  res.send('Secret area');
});

app.get('/public', function (req, res) {
  // Does not require an accessToken
  res.send('Public area');
});

// Error handling
app.use(app.oauth.errorHandler());

app.listen(3000);
