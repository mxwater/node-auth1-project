// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!

const router = require('express').Router();
const bcrypt = require('bcryptjs');
const Users = require('../users/users-model');

const {
  checkPasswordLength,
  checkUsernameExists,
  checkUsernameFree,
} = require('../auth/auth-middleware');  // Make sure the path is correct

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post('/register', checkUsernameFree, checkPasswordLength, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 12); // Hash password
    const newUser = await Users.add({ username, password: hashedPassword }); // Add new user to the database
    res.status(201).json(newUser); // Return new user data
  } catch (error) {
    next(error); // Pass errors to the error handler
  }
});

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
  router.post('/login', checkUsernameExists, (req, res, next) => {
    const { password } = req.body;
    if (bcrypt.compareSync(password, req.user.password)) {
      req.session.user = req.user; 
      res.json({message: `Welcome ${req.user.username}`})
    } else {
      next({status: 401, message: 'Invalid credentials'})
    }
  });
  

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get('/logout', (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        res.status(500).json({ message: 'Failed to log out' });
      } else {
        res.clearCookie('chocolatechip'); // Clear the session cookie
        res.json({ message: "Logged out successfully" });
      }
    });
  } else {
    res.status(200).json({ message: "No session found" }); // No session to log out
  }
});

// Export the router to be used in other modules
module.exports = router;
