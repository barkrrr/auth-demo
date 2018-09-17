'use strict';

const express = require('express');
const router = express.Router();
const User = require('../models/user');
const bcrypt = require('bcrypt');
const saltRounds = 10;

router.get('/signup', (req, res, next) => {
  if (req.session.currentUser) {
    return res.redirect('/');
  }
  const formData = req.flash('signup-form-data');
  const formErrors = req.flash('signup-form-error');
  const data = {
    message: formErrors[0],
    fields: formData[0]
  };
  res.render('signup', data);
});

router.post('/signup', (req, res, next) => {
  if (req.session.currentUser) {
    return res.redirect('/');
  }
  const { username, password } = req.body;
  if (!username || !password) {
    req.flash('signup-form-error', 'Username and password are mandatory!');
    req.flash('signup-form-data', { username, password });
    return res.redirect('/auth/signup');
  }

  User.findOne({ username })
    .then((result) => {
      if (result) {
        req.flash('signup-error', 'Username already taken');
        req.flash('signup-data', { username });
        return res.redirect('/auth/signup');
      }
      const salt = bcrypt.genSaltSync(saltRounds);
      const hashedPassword = bcrypt.hashSync(password, salt);

      const user = new User({ username, password: hashedPassword });
      return user.save()
        .then(() => {
          req.session.currentUser = user;
          res.redirect('/');
        });
    })
    .catch(next);
});

router.get('/login', (req, res, next) => {
  if (req.session.currentUser) {
    return res.redirect('/');
  }
  const formData = req.flash('login-data');
  const formErrors = req.flash('login-error');
  const data = {
    message: formErrors[0],
    fields: formData[0]
  };
  res.render('login', data);
});

router.post('/login', (req, res, next) => {
  if (req.session.currentUser) {
    return res.redirect('/');
  }
  const { username, password } = req.body;
  if (!username || !password) {
    req.flash('login-error', 'Username and password are mandatory!');
    return res.redirect('/auth/login');
  }
  User.findOne({ username })
    .then((result) => {
      if (!result) {
        req.flash('login-error', 'User doesn\'t exist');
        return res.redirect('/auth/login');
      }
      if (!bcrypt.compareSync(password, result.password)) {
        req.flash('login-error', 'Password is incorrect');
        return res.redirect('/auth/login');
      }
      req.session.currentUser = result;
      res.redirect('/');
    });
});

router.post('/logout', (req, res, next) => {
  delete req.session.currentUser;
  res.redirect('/');
});

module.exports = router;
