const User = require('../model/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mailgun = require("mailgun-js");
const _ = require('lodash');
require('dotenv').config();

const DOMAIN = process.env.MAILGUN_DOMAIN_NAME;
const api_key = process.env.MAILGUN_API_KEY
var mg = require('mailgun-js')({apiKey: api_key, domain: DOMAIN});

// Normal signup 
const signup = async (req, res, next) => {
	let { name, email, password } = req.body;
	let exisitingUser;

	if (password){
		if (password.length >= 3) {

			if (email == '' && name == '') {
				console.log("email", email);
				console.log("name", name);
				return res.status(400).json({ message: "name or email is empty" });
			} else {
				try{
					exisitingUser = await User.findOne({ email: email })
				} catch (err) {
					return new Error(err);
				};

				if (exisitingUser) {
					return res.status(400).json({message: "User already exists, so login"});
				}

				const hashedPassword = bcrypt.hashSync(password);
			    const user = new User({
			      name: name,
			      email: email,
			      password: hashedPassword,
			      token: ''
			  });

				try {
					await user.save();
				} catch (err) {
					return new Error(err);
				}

				return res.status(201).json({ message: user });
			}

		} else {
			return res.status(400).json({ message: "password is weak" });
		}
	}
};

// signup using email-Verification
const signupEmail = async (req, res, next) => {
	console.log(req.body);
	const { name, email, password } = req.body;

	User.findOne({ email }).exec(function (err, user) {
		if (user) {
			return res.json(400).json({ error: "User with this email already exists" });
		}

		const token = jwt.sign({ name, email, password }, process.env.JWT_SECRET, { expiresIn: '30m' });

		const data = {
			from: 'noreply@hello.com',
			to: email,
			subject: 'Account Activation Link',
			html:`
				<h2> Click here to activate your account </h2>
				<p>${process.env.CLIENT_URL}authentication/activate/${token}</p>
			`
		};
		mg.messages().send(data, function (error, body) {
			
			if(err) {
				return res.json({error: err.message});
			}

			return res.json({ message: "an email has been sent kindly check" });

			console.log(body);
		});

	}
)};

const activateAccount = async (req, res, next)	=> {
	const { token } = req.body;
	if (token) {
		jwt.verify(token, process.env.JWT_SECRET, function (err, decodedToken) {
			if (err) {
				return res.status(400).json({ error: 'Incorrect or expired token' });
			}
			const { name, email, password } = decodedToken;

			User.findOne({ email }).exec(function ( err, user  ) {
				
				if (user) {
					return res.status(400).json({ error: "user exists" });
				}
				
				let newUser = new User({ name, email, password });
				newUser.save(function (err, success) {
					if (err) {
						console.log("error in signup while Activation ", err);
						return res.status(400).json({ error: 'Error while Activation' });
					}
					res.json({ message: "signup success!" });
				})
			});

		});
	} else {
		return res.json({ error: "something went wrong" })
	}
};

const login = async (req, res, next) => {

	const { email, password } = req.body;
	let exisitingUser;
	try {
		exisitingUser = await User.findOne({ email: email });
	} catch (err) {
		return new Error(err)
	}

	if (!exisitingUser) {
		return res.status(400).json({ message: "user not found kindly signup" });
	}
	
	const isPasswordCorrect = bcrypt.compareSync(password, exisitingUser.password);
	if (!isPasswordCorrect) {
		return res.status(400).json({ message: "Inavlid  Password" });
	}

	const token = jwt.sign({ id: exisitingUser._id }, process.env.JWT_SECRET, {
		expiresIn: "1hr"
	});

	res.cookie(String(exisitingUser._id), token, {
		path: '/',
		expires: new Date(Date.now() + 1000 * 30 ),
		httpOnly: true,
		sameSite: 'lax'
	});

	let updatedBody = token;


    try{
        const updatedUser = await User.findByIdAndUpdate(
        	exisitingUser._id, 
        	{ token: updatedBody },
        	{ new: true }
     );
        res.status(200).json(updatedUser)
	    } catch(err) {
	       next(err);
	    }

	return res.status(200).json({ 
		message: "logged in", 
		user: exisitingUser, 
		token 
	});

};

const verifyToken = async (req, res, next) => {

	const {email} = req.body;
	const cookies = req.headers.cookie;
	const token = cookies.split("=")[1];
	const tokenCookie = token.split(";")[0];

	try {

		const user=await User.findOne({ email: email }).select('token')
		console.log("utok:",user.token);
		const userToken=user.token;
        
		if(tokenCookie == userToken){
			console.log("success");
			return res.status(200).json({ message: "User found" });		
		}
		else {
			console.log("fail");
			return res.status(200).json({ message: "User not found" });
		}
		
	} catch (err) {
		return new Error(err);
	}
	if (!user) {
		return res.status(404).json({ message: "User not found" });
	}

};

const forgotPassword = async (req, res, next) => {
	const { email } = req.body;

	User.findOne({ email }, function (err, user) {
		if (err || !user) {
			return res.status(400).json({ error: "user with this email already exists" });
		}

		const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {expiresIn: '30m'});
		const data = {
			from: 'noreply@narenltk.com',
			to: email,
			subject: 'Account forgotPassword Link',
			html:`
				<h2> Click here to reset your password </h2>
				<p>${process.env.CLIENT_URL}resetpassword/${token}</p>
			`
		};

		return user.updateOne({ resetLink: token }, function (err, success) {
			if (err) {
				return res.status(400).json({ error: "reset password link error" });
			} else {
				mg.messages().send(data, function (err, body) {
					if (err) {
						return res.json({ error: err.message });
					}
					return res.json({ message: 'Email has been sent, follow the instruction' });
				});
			}
		});
	});
};

const resetPassword = async (req, res, next) => {
	const { resetLink, newPass } = req.body;

	if (resetLink) {
		jwt.verify(resetLink, process.env.JWT_SECRET, function (err, decodedData) {
			if (err) {
				return res.status(400).json({ error: "Token Incorrect" });
			}

			User.findOne({ resetLink }, function (err, user) {
				if (err || !user) {
					return res.status(400).json({ error: "user with this token is not available" });
				}

				const obj = {
					password : newPass
				}

				user = _.extend(user, obj);
				user.save(function (err, result) {
					if (err) {
						return res.status(400).json({ error: "reset you error" });
					} else {
						return res.status(200).json({ message: "you password has been changed"});
					}
				});

			});

		});
	} else {
		return res.status(400).json({ error: "authentication error" });
	}

};

const getUser = async (req, res, next) => {
	const cookies = req.headers.cookie;
  	console.log("cookies: ", cookies);
  	const token = cookies.split("=")[0];
  	console.log("token: ", token);
	const userId = req.id;
	let user;
	// console.log("getUser user id: ", req.id);
	try {
		user = await User.findById(userId);
		// console.log("getUser user: ", req.id);
	} catch (err) {
		return new Error(err);
	}
	if (!user) {
		return res.status(404).json({ message: "User not found" });
	}
	return res.status(200).json({user: user});
}

module.exports = {
	signup,
	login,
	verifyToken,
	signupEmail,
	resetPassword,
	forgotPassword,
	activateAccount,
	getUser
}

// exports.signup          = signup;
// exports.login           = login;
// exports.verifyToken     = verifyToken;
// exports.signupEmail     = signupEmail;
// exports.activateAccount = activateAccount;
// exports.forgotPassword  = forgotPassword;
// exports.resetPassword   = resetPassword;
// exports.getUser = getUser;