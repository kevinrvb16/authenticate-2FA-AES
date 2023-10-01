require("dotenv").config();
const crypto = require('crypto');
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const ejs = require("ejs");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook"); 
const findOrCreate = require("mongoose-findorcreate");
const otplib = require('otplib');
const qrcode = require('qrcode');

const app = express();

app.use(express.static("public"));
app.set("view engine","ejs");
app.use(bodyParser.urlencoded({extended: true}));


function gerarNumeroAleatorioSeguro() {
  const numeroAleatorio = crypto.randomBytes(4).readUInt32LE(0);
  return numeroAleatorio;
}

const randomkey = gerarNumeroAleatorioSeguro()

app.use(session({
    secret: "randomkey",
    resave: false,
    saveUninitialized: true
}))

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    cellphone: String,
    secret: String,
})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("user", userSchema)

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.name, cellphone: user.cellphone });
    });
  });
  
passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });


app.get("/", function(req, res){
    res.render("home")
})


app.get("/login", function(req, res){
    res.render("login")
})

app.get("/register", function(req, res){
    res.render("register")
})

app.get("/submit", function(req, res){
    if (req.isAuthenticated()){
        res.render("submit")
    }else{
        res.redirect("/login");
    }
})

app.get("/logout", function(req, res){
    req.logOut(function(error){
        if (error){
            console.log(error)
        }else{
            res.redirect("/")
        }
    });
})

app.post("/register", function(req, res){
    User.register({username: req.body.username, cellphone: req.body.cellphone}, req.body.password)
    .then(function(user){
        passport.authenticate("local")(req,res, function(){
            res.redirect("/qrcode")
        })
    }).catch(function(error){
        console.log(error)
        res.redirect("/register")
    })
})

app.get("/secrets", function(req,res){
  User.find({"secret": {$ne: null}})
  .then(function(users){
    if (users){
      res.render("secrets", {usersWithSecrets: users})
    }
  }).catch(function(err){
    console.log(err)
  })
})

app.get("/qrcode", function(req,res){
  User.findById(req.user.id)
  .then(function(user){
    if (user){
      const qrcode_url = integrateWithGoogleAuthenticator(user)
      res.render("qrcode", {qrcode_url})
    }
  }).catch(function(err){
    console.log(err)
  })
})

app.post("/submit", function(req, res){
  const submitedSecret = req.body.secret
  
  User.findById(req.user.id)
  .then(function(user){
    user.secret = submitedSecret;
    user.save()
    .then(function(){
      res.redirect("/secrets")
    })
  }).catch(function(err){
    console.log(err)
  })

})

app.post('/login', passport.authenticate('local', { failureRedirect: '/login' }), function(req, res) {
    res.redirect('/secrets');
});

app.listen(3000, function(){
    console.log("Server started on port 3000")
})

function integrateWithGoogleAuthenticator(user) {
  const secretKey2FA = otplib.authenticator.generateSecret();

  // Gere uma URL para o código QR
  const otpauthUrl = otplib.authenticator.keyuri(user.username, user.username, secretKey2FA);
  console.log('otpauthUrl:', otpauthUrl);
  console.log('secretKey2FA:', secretKey2FA);
  console.log('user:', user);
  // Crie o código QR
  const qrcode_url = qrcode.toDataURL(otpauthUrl, (err, data_url) => {
    if (err) {
      console.error(err);
      return;
    }

    // Exiba ou salve o data_url para gerar o código QR
    console.log('Código QR gerado:', data_url);
    return data_url;
  });
  return qrcode_url;
}

