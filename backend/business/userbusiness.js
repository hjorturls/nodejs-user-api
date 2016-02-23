var mongoose = require('mongoose');
var User = require('../models/user.js')
var throwjs = require('throw.js');
var validator = require('validator');
var async = require('async');
require('../utils/stringHelpers.js');
var bcrypt = require('bcrypt');
var request = require('request');
var config = require('../config');
var generatePassword = require('password-maker');
var jwt = require('jsonwebtoken');

/*
  Search users
*/
function searchUsers(req, res, next) {
  var email = req.query.email;
  User.find({'email' : email}, function(err, users) {
    if (users.length === 0) {
      return next(new throwjs.badRequest("No users found with the email: " + email));
    }
    else if (err){
      return next(new throwjs.internalServerError(err));
    }
    return res.json(users);
  });
}

/* 
  Gets a user from an access token
*/
function getMyUser(req, res, next) {
  User.findById(req.user.id, function(err, user) {
    if (!user){
      return next(new throwjs.notFound());
    }
    else if (err){
      return next(new throwjs.internalServerError(err));
    }
    return res.json(user);
  });
}

/*
  Gets a single user based on id
*/
function getUser(req, res, next) {
  User.findById(req.params.id, function(err, user) {
    if (!user){
      return next(new throwjs.notFound());
    }
    else if (err){
      return next(new throwjs.internalServerError(err));
    }
    return res.json(user);
  });
}

/*
  Deletes a user from the db
*/
function deleteUser(req, res, next) {
  User.findById(req.params.id, function(err, user) {
    if (!user){
      return next(new throwjs.notFound());
    }
    else if (err){
      return next(new throwjs.internalServerError(err));
    }
    user.remove();
    return res.sendStatus(204);
  });
}

/*
Extracts the user information from the header. If using basic authentication, the username and password is base 64 encoded
in the header. If Fb token is passed in, we must verify the token with facebook and extract the user information from there first
*/
function getUserFromHeader(req, res, next) {
  var user = new User();
  var authHeader = req.headers["authorization"];
  if (!authHeader) {
    return next(new throwjs.badRequest("The Authorization header is missing"));
  }
  
  if (authHeader.startsWith('Basic')) {
    var buffer = new Buffer(authHeader.replace('Basic ', ''), 'base64');
    var authorization = buffer.toString('ascii');
    var userPass = authorization.split(':');
    if (userPass.length != 2) {
      return next(new throwjs.badRequest("Could not extract the email or password from the auth header"))
    }
    
    user.email = userPass[0];
    if (!validator.isEmail(user.email)) {
      return next(new throwjs.badRequest("Invalid email"));
    }
    
    // Set the name if it is supplied in the request
    if (req.body.name) {
      user.name = req.body.name;
    }
    
    user.password = userPass[1];
    req.user = user;
    next();
  }
  else if (authHeader.startsWith('Fb')) {
    var token = authHeader.replace('Fb ', '');
    request({url:config.facebook.me + token}, function(err, response, body) {
      if(err) { 
        return next(new throwjs.unauthorized(err)); 
      }
      if (response.statusCode != 200) {
        console.log(body);
        return next(new throwjs.unauthorized("The facebook token is expired")); 
      }
      var json = JSON.parse(body);
      user.email = json.email;
      user.name = json.name;
      user.externalUser.userId = json.id;
      user.externalUser.userType = "fb";
      user.password = generatePassword(12);
      req.user = user;
      next();
    });
  }
  else {
    return next(new throwjs.badRequest('Unknown auth schema'));
  }
}

/*
  Creates a new user in the db
*/
function createUser(req, res, next) {
  var user = req.user;
  User.find({ 'email' : user.email }, function(err, existingUser) {
    if (existingUser.length > 0) {
      // email is in use - return 409 (Conflict)
      return next(new throwjs.conflict('The email ' + user.email + ' is already in use'));
    }
    
    // Set the name if it is supplied in the request
    if (req.body.name) {
      user.name = req.body.name;
    }

    user.createdOn = Date.now();
    // Hash the password
    user.password = bcrypt.hashSync(user.password, 8);
    // If email is not taken, we save the user
    user.save(function(err, user) {
      if (err) {
        return next(new throwjs.internalServerError(err));
      }
      // Set the location header for our newly created user resource
      var location = "/users/" + user.id;
      res.setHeader("Location", location);
      var createdUser = {};
      createdUser.id = user._id;
      createdUser.name = user.name;
      createdUser.email = user.email;
      if (user.externalUser) {
        createdUser.externalUser = {};
        createdUser.externalUser.userId = user.externalUser.userId;
        createdUser.externalUser.userType = user.externalUser.userType;
      }
      createdUser.token = jwt.sign(user, config.jwtsecret, {
        expiresIn: 86400 // expires in 24 hours
      });
      return res.status(201).send(createdUser);
    });
  });
}

function authenticate(req, res, next) {
  var user = req.user;
  // Verify the user/pass since we're not using 3rd party auth for this user
  User.findOne( { 'email' : user.email }, function (err, existingUser) {
    if (!existingUser) {
      // User doesn't exist
      return next(new throwjs.unauthorized('Invalid credentials'));
    }
    var validHash = bcrypt.compareSync(user.password, existingUser.password);
    if (!user.externalUser.userId && !validHash) {
      return next(new throwjs.unauthorized('Invalid credentials'));
    }
    
    var tokenUser = {id: existingUser.id, email: existingUser.email };
    if (existingUser.isAdmin) {
      tokenUser.isAdmin = true;
    }
    var token = jwt.sign(tokenUser, config.jwtsecret, {
      expiresIn: 7200 // expires in 2 hours
    });
    return res.status(200).send({ token : token });
  });
  
}

/*
  Validates a jwt token
*/
function validateToken(req, res, next) {
  var token = req.headers["authorization"];
  if (!token) {
    return next(new throwjs.badRequest("The Authorization header is missing"));
  }
  if (!token.startsWith("Bearer")) {
    return next(new throwjs.badRequest("Invalid auth schema. Should be 'Bearer'"));
  }
  token = token.replace('Bearer ', '');
  jwt.verify(token, config.jwtsecret, function(err, user) {
    if (err) {
      return next(new throwjs.unauthorized("Invalid token: " + err.message));
    }
    if (!user) {
      return next(new throwjs.unauthorized("Invalid token"));
    }
    req.user = user;
    next();
  });
}

/*
  Validates that the current user is an admin or not.
*/
function validateAdmin(req, res, next) {
  if (req.user.isAdmin != true) {
    return next(new throwjs.unauthorized("Invalid token"));
  }
  next();
}

exports.searchUsers = searchUsers;
exports.getUser = getUser;
exports.getMyUser = getMyUser;
exports.deleteUser = deleteUser;
exports.createUser = createUser;
exports.getUserFromHeader = getUserFromHeader;
exports.authenticate = authenticate;
exports.validateToken = validateToken;
exports.validateAdmin = validateAdmin;