require("dotenv").config();
const express = require("express")
const app = express()
const ejs = require("ejs")
const mongoose = require("mongoose")
const encrypt = require("mongoose-encryption")
// const md5 = require("md5")
const bcrypt = require("bcrypt")
const saltRounds = 10
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const findOrCreate = require("mongoose-findorcreate");


app.use(express.static("public"))
app.use(express.urlencoded({
    extended: true
}))
app.set("view engine", "ejs")

app.use(session({
    secret: "ThisIsASecret",
    resave: false,
    saveUninitialized: false
}))

app.use(passport.initialize());

app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB")

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema)

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req, res) => {
    res.render("home")
})
app.get("/login", (req, res) => {
    res.render("login")
})
app.get("/register", (req, res) => {
    res.render("register")
})

app.get("/logout",(req, res)=>{
    req.logOut();
    res.redirect("/");
})

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });


app.get("/secrets", (req, res) => {
   User.find({secret:{$ne:null}},(err, usersFound)=>{
       if (err) {
           console.log(err);
       }
       else if (usersFound) {
           res.render("secrets",{usersWithSecrets : usersFound})
       }
   })
})

app.get("/submit",(req, res)=>{
    if(req.isAuthenticated){
        res.render("submit")
    }
    else{
        res.redirect("/login")
    }
});

app.post("/submit",(req, res)=>{
    const secretSubmitted = req.body.secret;
    console.log(req.user._id);
    User.findById(req.user._id,(err, userFound)=>{
        if(err){
            console.log(err);
        }
        else if (userFound) {
            userFound.secret = secretSubmitted;
            userFound.save(()=>{
                res.redirect("/secrets");
            })
        }
    })
})

app.post("/register", (req, res) => {
    User.register({
        username: req.body.username
    }, req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            })
        }
    })

})

app.post("/login", (req, res) => {
    // create an object for user

    const user = new User({
        username: req.body.username,
        passport: req.body.password
    });

    req.login(user, (err)=>{
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local")(req, res, ()=>{
                res.redirect("/secrets")
            })
        }
    })

})


app.listen(3000, () => {
    console.log("Server listening on port 3000");
})