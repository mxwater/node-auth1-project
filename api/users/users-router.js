// Require the `restricted` middleware from `auth-middleware.js`. You will need it here!
const express = require('express');
const router = express.Router();
const Users = require('./users-model');
const { restricted } = require('../auth/auth-middleware'); 

/**
  [GET] /api/users
 
  This endpoint is RESTRICTED: only authenticated clients
  should have access.

  response:
  status 200
  [
    {
      "user_id": 1,
      "username": "bob"
    },
    // etc
  ]

  response on non-authenticated:
  status 401
  {
    "message": "You shall not pass!"
  }
 */

router.get('/', restricted, async (req, res, next) => {
  try {
    const users = await Users.find();  
    res.status(200).json(users);
  } catch (error) {
    next(error); 
  }
});

// Export the router to be used in other modules
module.exports = router;
