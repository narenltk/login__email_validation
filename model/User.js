const mongoose = require('mongoose');
const { Schema } = mongoose;
const bcrypt = require('bcryptjs');

const userSchema = new Schema({
	name: {
		type: String,
		require: true,
		max: 64
	},
	email: {
		type: String,
		require: true,
		unique: true
	},
	password: {
		type: String,
		require: true,
		minlength: 3
	},
	resetLink: {
		type: String,
		default: ''
	}
	, 
	token: {
		type: String,
		require: true,
		unique: true
	}
}, {timestamps: true});

module.exports = mongoose.model('User', userSchema);