const express = require('express');
const authRoutes = express.Router();
const passport = require('passport');
const bcrypt = require('bcryptjs');
const User = require('../models/user-model');

authRoutes.post('/signup', (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;

  if (!username || !password) {
    res.status(400).json({
      message: 'Prease provide a username and password'
    });
    return
  }
  if (password.length < 8) {
    res.status(400).json({
      message: 'Please make sure your password is at least 8 characters long.'
    });
    return
  }
  User.findOne({ username }, (err, foundUser) => {
    if (err) {
      res.status(500).json({
        message: 'Username request went bad :('
      });
      return
    }
    if (foundUser) {
      res.status(400).json({
        message: 'This username has already been taken. Please choose another one.'
      });
      return
    }

    const salt = bcrypt.genSaltSync(10);
    const hashPass = bcrypt.hashSync(password, salt);

    const aNewUser = new User({
      username,
      password: hashPass
    });
    aNewUser.save(err => {
      if (err) {
        res.status(400).json({
          message: 'Something went wrong while trying to save user in DB.'
        });
        return
      }
      req.login(aNewUser, (err) => {
        if (err) {
          res.status(500).json({
            message: "Login after signup din't work"
          });
          return
        }
        res.status(200).json(aNewUser);
      })
    })
  })
})

authRoutes.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, theUser, failureDetails) => {
    if (err) {
      res.status(500).json({
        message: 'Unable to authenticate user'
      });
      return
    }
    if (!theUser) {
      res.status(401).json(failureDetails);
      return
    }
    req.login(theUser, (err) => {
      if (err) {
        res.status(500).json({
          message: "Session login went bad."
        });
        return
      }
      res.status(200).json(theUser);
    });
  })(req, res, next); //executando direto a funcao que foi retornada
});

authRoutes.post('/logout', (req, res, next) => {
  req.logout();
  res.status(200).json({ message: 'Log out success!' });
});


authRoutes.get('/loggedin', (req, res, next) => {
  if (req.isAuthenticated()) {
      res.status(200).json(req.user);
      return;
  }
  res.status(403).json({ message: 'Unauthorized' });
});

module.exports = authRoutes