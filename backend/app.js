var express = require('express')
var bodyParser = require('body-parser')
var userRoute = require('./routes/users');
var http = require('http');
var path = require('path');
var mongoose = require('mongoose');
var fs = require('fs');
var throwjs = require('throw.js');
var logger = require('winston');
var config = require('./config');
var morgan = require('morgan');

var app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

mongoose.connect(config.mongo.connection);

var port = process.env.PORT || 8080;        // set our port

fs.readdirSync('./models').forEach(function(filename) {
  if (~filename.indexOf('.js')) require('./models/' + filename);
});

// use morgan to log requests to the console
app.use(morgan('dev'));

app.use('/users', userRoute);

app.use(function(err, req, res, next) {
    logger.error(err);
    
    if (req.app.get('env') !== 'development' &&
        req.app.get('env') !== 'test') {
 
        delete err.stack;
    }
 
    res.status(err.statusCode || 500).json(err);
 
});

var server = app.listen(3000, function() {
  var port = server.address().port;
  console.log("Server running on http://localhost:%s", port);
});

module.exports = config;
