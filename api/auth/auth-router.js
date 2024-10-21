

// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!

const router = require('express').Router();
const bcrypt = require('bcryptjs');
const Users = require('../users/users-model');

const {
  checkPasswordLength,
  checkUsernameExists,
  checkUsernameFree,
} = require('./auth-middleware');


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
    const { username, password } = req.body;
    Users.findBy({ username }).then(user => {
      if (user && bcrypt.compareSync(password, user.password)) { // Verify password
        req.session.user = user; // Set user session
        res.json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: "Invalid credentials" }); // Wrong credentials
      }
    }).catch(next); // Error handling
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
  

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router


