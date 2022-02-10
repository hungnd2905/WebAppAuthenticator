//jshint esversion:6

/////////////////////////Config passport google oauth2//////////////////////////

//dotenv: package for storing configuration in the environment seperate from code.
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

// Session : Session data is not saved in the cookie itself, just the session ID. Session data is stored server-side.
const session = require('express-session');

//Passport strategy for authenticating with Google using the OAuth 2.0 API.
//https://www.passportjs.org/packages/passport-google-oauth20/
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;

// package that make method findOrCreate from passport works with mongoose
const findOrCreate = require("mongoose-findorcreate")

// use packages
const app = express();
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

//use session
app.use(session({
  secret: "my little secret.",
  resave:false,
  saveUninitialized: false
}));

//initialize passport and use passport to manage session
app.use(passport.initialize());
app.use(passport.session());

//connect to local MongoDB "userDB"
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

//create Mongo Schema
const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  secret: String

});

//combine passport with mongoose
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//create Mongo-model User
const User = new mongoose.model("User",userSchema);

//config passport with Mongo-model
passport.use(User.createStrategy());

passport.serializeUser(function(user, done){
  done(null, user.id);
});

passport.deserializeUser(function(id, done){
  User.findById(id, function(err,user){
    done(err,user);
  });
});

//config passport google oauth2
//source: https://www.passportjs.org/packages/passport-google-oauth20/
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    //fix error from "Google +"
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

/////////////////////////////////////////Routes/////////////////////////////////
app.get("/", function(req,res){
  res.render("home");
});


app.get("/auth/google",
  // route to Google login page
  // source: https://www.passportjs.org/packages/passport-google-oauth20/
  passport.authenticate("google", {scope: ["profile"]})
);

//the route should be the same as "Authorized redirect URIs" in "Credentials" \ "Client ID for Web application"
// in www.console.developers.google.com
app.get("/auth/google/secrets",
//response from google after login google account
//source: https://www.passportjs.org/packages/passport-google-oauth20/
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets page.
    res.redirect("/secrets");
  });

app.get("/login", function(req,res){
  res.render("login");
});

app.get("/register", function(req,res){
  res.render("register");
});

app.get("/secrets", function(req,res){
  //search for all secrets in database that is not null (ne)
  User.find({"secret:": {$ne: null}}, function(err, foundUsers){
    if(err){
      console.log(err);
    } else {
      if(foundUsers){
        res.render("secrets", {usersWithSecret: foundUsers });
      }
    }
  });
});

app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req,res){
  const submittedSecret = req.body.secret;
  User.findById(req.user.id, function(err, foundUser){
    if(err){
      console.log(err);
    } else {
      if (foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout", function(req,res){
  req.logout();
  res.redirect("/");
});

app.post("/register", function(req,res){

  User.register({username: req.body.username}, req.body.password, function(err, user){
    if(err){
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  });

});

app.post("/login", function(req,res){
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if(err){
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  })
});

app.listen(3000, function(){
  console.log("Server started on port 3000.");
})
