var express = require('express');
var mongoose = require('mongoose');
var User = require('../models/user.js')
var throwjs = require('throw.js');
var validator = require('validator');
require('../utils/stringHelpers.js');
var router = express.Router();
var bcrypt = require('bcrypt');
var userbusiness = require('../business/userbusiness.js');

/*
  Search for users by email
*/
router.get('/', userbusiness.validateToken, userbusiness.searchUsers);

/*
  Get the user associated with the access token
*/
router.get('/me', userbusiness.validateToken, userbusiness.getMyUser);

/*
  Get user by id
*/
router.get('/:id', userbusiness.validateToken, userbusiness.getUser);

/*
  Deletes a user by id
*/
router.delete('/:id', userbusiness.validateToken, userbusiness.validateAdmin, userbusiness.deleteUser);

/*
  Creates a new user
*/
router.post('/', userbusiness.getUserFromHeader, userbusiness.createUser);

/*
  Authenticates a user
*/
router.post('/auth', userbusiness.getUserFromHeader, userbusiness.authenticate);

module.exports = router;