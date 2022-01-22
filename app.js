require("dotenv").config();
const express = require("express")
const app = express()
const ejs = require("ejs")
const mongoose = require("mongoose")
const encrypt = require("mongoose-encryption")
// const md5 = require("md5")
const bcrypt = require("bcrypt")
const saltRounds = 10

const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const e = require("express");


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
    password: String
})

userSchema.plugin(passportLocalMongoose);


const User = mongoose.model("User", userSchema)

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

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

app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
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