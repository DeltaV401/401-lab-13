'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const users = new mongoose.Schema({
  username: {type:String, required:true, unique:true},
  password: {type:String, required:true},
  email: {type: String},
  role: {type: String, default:'user', enum: ['admin','editor','user']},
});

users.pre('save', async function() {
  if (this.isModified('password'))
  {
    this.password = await bcrypt.hash(this.password, 10);
  }
});

users.statics.authenticateToken = async function(token) {
  try {
    let data = jwt.decode(token);
    let user = await this.findById(data.id);
    if(user && jwt.verify(token, user.generateSecret())) {
      return user;
    }
    return null;
  }
  catch(err) {
    console.warn(`This - ${err} - says you really goofed.`);
    return null;
  }
}

users.statics.createFromOauth = async function(email) {

  if(! email) { return Promise.reject('Validation Error'); }

  let user = await this.findOne({ email });
  if(user) {
    return user;
  }
  return this.create({
    username: email,
    password: Math.random() * Math.random(),
    email,
  });
};

users.statics.authenticateBasic = function(auth) {
  let query = {username:auth.username};
  return this.findOne(query)
    .then( user => user && user.comparePassword(auth.password) )
    .catch(error => {throw error;});
};

users.methods.comparePassword = function(password) {
  return bcrypt.compare( password, this.password )
    .then( valid => valid ? this : null);
};

users.methods.generateToken = function() {
  let token = {
    id: this._id,
    role: this.role,
  };
  let options = {
    expiresIn: "15m",
  };
  return jwt.sign(token, process.env.SECRET, options);
};

users.methods.generateSecret = function() {
  return (process.env.SECRET || 'changeit');
}

module.exports = mongoose.model('users', users);
