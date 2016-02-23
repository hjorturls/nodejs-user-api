var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var schema = new Schema({
	name: String,
	email: String,
	password: String,
	createdOn: Date,
	externalUser: {
		userType: String,
		userId: String
	}
});

schema.set('toJSON', { transform: function(doc, obj, options) { 
		delete obj.password; 
		delete obj.__v;
		obj.id = obj._id;
    delete obj._id;
		return obj; 
	} 
});

module.exports = mongoose.model('user', schema);