const express = require('express');
const app = express();
const mongoose = require('mongoose');
const cors = require('cors');
const router = require('./routes/userRoutes.js');
const cookieParser = require('cookie-parser');
require('dotenv').config();

// const mongUrl = 'mongodb+srv://narenltk:narenltk@cluster0.gazgu23.mongodb.net/?retryWrites=true&w=majority';

const corsOpt = {
	origin: '*',
	method: [
		'GET',
		'POST',
		'PUT',
		'DELETE'
	],
	allowHeaders: [
		'Content-Type',
	],
};

const connect = async () => {
	try {
		await mongoose.connect(process.env.MONGOURL, {
			useNewUrlParser: true,
			useUnifiedTopology: true,
		});
		console.log("established MongoDB connection");
	} catch (err) {
		console.log("mongoose Error", err);
	}
};

app.use(cookieParser());
app.use(cors(corsOpt));
app.use(express.json());

app.listen(process.env.PORT, (req, res) => {
	connect();
	console.log('server started on port ' + process.env.PORT);
});

app.use('/api', router);