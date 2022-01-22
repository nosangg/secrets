require("dotenv").config();
const express = require("express")
const app = express()
const ejs = require("ejs")
const mongoose = require("mongoose")
const encrypt = require("mongoose-encryption")
// const md5 = require("md5")
const bcrypt = require("bcrypt")
const saltRounds = 10

app.use(express.static("public"))
app.use(express.urlencoded({extended:true}))
app.set("view engine", "ejs")

mongoose.connect("mongodb://localhost:27017/userDB")

const userSchema = new mongoose.Schema({
    email: String,
    password: String
})

const User = mongoose.model("User", userSchema)

app.get("/",(req,res)=>{
    res.render("home")
})
app.get("/login",(req,res)=>{
    res.render("login")
})
app.get("/register",(req,res)=>{
    res.render("register")
})

app.post("/register",(req, res)=>{
    bcrypt.hash(req.body.password, saltRounds,(err, hash)=>{
        if(!err){
            const newUser = new User({
                email: req.body.username,
                password: hash
            })
            newUser.save((err)=>{
                if(err){
                    console.log(err);
                }
                else{
                    res.render("secrets");
                }
            })
        }
    })
    
})

app.post("/login",(req,res)=>{

    const username = req.body.username;
    const password = req.body.password;

    User.findOne({email: username},(err, foundUser)=>{
        if(err){
            console.log(err);
        }
        else if(foundUser){
            bcrypt.compare(password, foundUser.password,(err, result)=>{
                if(!err && result === true){
                    res.render("secrets")
                }
            })
        }
    })
})


app.listen(3000, ()=>{
    console.log("Server listening on port 3000");
})