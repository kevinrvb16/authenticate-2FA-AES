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
let secretKey2FA = otplib.authenticator.generateSecret();
const CryptoJS = require('crypto-js');
const algorithm = 'aes-256-gcm';
require('crypto-js/aes');
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
    messages: Array
})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("user", userSchema)

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.name, cellphone: user.cellphone, messages: user.messages });
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

app.get("/chat", function(req, res){
  if (req.isAuthenticated()){
      res.render("chat", req.username)
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
    User.register({username: req.body.username, cellphone: req.body.cellphone, messages: []}, req.body.password)
    .then(function(user){
        passport.authenticate("local")(req,res, function(){
            res.redirect("/qrcode")
        })
    }).catch(function(error){
        console.log(error)
        res.redirect("/register")
    })
})

app.get("/users", function(req,res){
  console.log(req.user)
  User.find({})
  .then(function(users){
    if (users){
      res.render("users", { users, eumesmo: req.user })
    }
  }).catch(function(err){
    console.log(err)
  })
})

app.post("/users", function(req,res){
  const username = req.body.username
    if (username){
      res.render("chat", {username})
    }
})

app.get("/qrcode", function(req,res){
  User.findById(req.user.id)
  .then(function(user){
    if (user){
      /* secretKey2FA = otplib.authenticator.generateSecret(); */
      // Gere uma URL para o código QR
      const otpauthUrl = otplib.authenticator.keyuri(user.id, user.name, secretKey2FA);
      // Crie o código QR
      qrcode.toDataURL(otpauthUrl, (err, data_url) => {
        if (err) {
          console.error(err);
          return;
        }
        // Exiba ou salve o data_url para gerar o código QR
        res.render("qrcode", {data_url})
      });
    }
  }).catch(function(err){
    console.log(err)
  })
})

app.post("/qrcode", function(req, res){

  // O código fornecido pelo usuário (geralmente inserido manualmente)
  const userProvidedCode = req.body.token;

  // Verificar se o código fornecido é válido
  const isValid = otplib.authenticator.check(userProvidedCode, secretKey2FA);
  // Exibir se o código é válido ou não
  if (isValid) {
    res.redirect("/users");
  } else {
    res.redirect("/qrcode");
  }

});

app.post("/chat", function(req, res){
  const { message, username } = req.body;

  const mensagemCifrada = encryptMessageWithGCM(message)

  sendMessage(mensagemCifrada, username)

  res.send({ success: true, message: 'Mensagem enviada com sucesso' });
})

function sendMessage(mensagemCifrada, username){
  User.findOne({username})
  .then(function(user){
    if (user){
      user.messages.push(mensagemCifrada)
      user.save()
    }
  }).catch(function(err){
    console.log(err)
  })
}

app.post('/login', passport.authenticate('local', { failureRedirect: '/login' }), function(req, res) {
    res.redirect('/verify');
});

app.post("/verify", function(req, res) {
  // O código fornecido pelo usuário (geralmente inserido manualmente)
  const userProvidedCode = req.body.token;

  // Verificar se o código fornecido é válido
  const isValid = otplib.authenticator.check(userProvidedCode, secretKey2FA);
  console.log(isValid)
  // Exibir se o código é válido ou não
  if (isValid) {
    res.redirect("/users");
  } else {
    res.redirect("/verify");
  }

});

app.get("/verify", function(req, res){
  res.render("verify", {username: req.body.username})
})

app.listen(3000, function(){
    console.log("Server started on port 3000")
})

function encryptMessageWithGCM(mensagemOriginal) {
  // Chave de criptografia e vetor de inicialização (IV)
  const chaveCriptografada = crypto.randomBytes(32); // 256 bits
  const iv = crypto.randomBytes(16); // 128 bits

  const mensagemCifrada = encryptMessage(mensagemOriginal, chaveCriptografada, iv);

  console.log('Mensagem Original:', mensagemOriginal);
  console.log('Mensagem Cifrada:', mensagemCifrada.content);
  return mensagemCifrada
/*   const mensagemDecifrada = decryptMessage(mensagemCifrada.ciphertext, mensagemCifrada.tag, chaveCriptografada, iv);
  console.log('Mensagem Decifrada:', mensagemDecifrada); */
}

// Função para cifrar a mensagem
function encryptMessage(message, key, iv) {
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  const encrypted = Buffer.concat([cipher.update(message, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    content: encrypted.toString('hex'),
    tag: tag.toString('hex'),
  };
}

// Função para decifrar a mensagem
function decryptMessage(encryptedData, key, iv) {
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(encryptedData.content, 'hex')), decipher.final()]);
  return decrypted.toString();
}