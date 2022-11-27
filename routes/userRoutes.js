const express = require('express');
const router = express.Router();
// const { signup, login, verifyToken, getUser } = require('../controllers/userController');
const { signup, 
	login, 
	verifyToken, 
	signupEmail, 
	activateAccount, 
	forgotPassword, 
	resetPassword,
	getUser 
} = require('../controllers/userController');

router.get('/', (req, res, next) => {
	res.send("Helo world");
});

router.post('/signup', signup);
router.post('/login', login);
router.get("/user", verifyToken);
router.post('/signupEmail', signupEmail)
router.post('/activateAccount', activateAccount);
router.put('/forgotPassword', forgotPassword);
router.put('/resetPassword', resetPassword);
router.get("/user", verifyToken, getUser);

module.exports = router;