require("dotenv").config();
const crypto = require('crypto');
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const ejs = require("ejs");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");
const otplib = require('otplib');
const qrcode = require('qrcode');
let secretKey2FA = otplib.authenticator.generateSecret();
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

mongoose.connect("mongodb+srv://kevinrvb16:pYG2PgR5Ml6m2yN8@cluster0.uvmral8.mongodb.net/?retryWrites=true&w=majority");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    cellphone: String,
    secret: String,
    messages: Array,
    salt: String
})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("user", userSchema)

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.name, cellphone: user.cellphone, messages: user.messages, salt: user.salt });
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
const getUserData = (req) => {
  let user = null;
  User.findOne({ username: req.body.username }).then(function(userData){
    user =userData;
  })
  return user;
};
app.post("/register", function(req, res){
  const salt = crypto.randomBytes(16).toString('hex');
    User.register({username: req.body.username, cellphone: req.body.cellphone, messages: [], salt} , req.body.password)
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
  let messagesDecrypted = []
  for (let i = 0; i < req.user.messages.length; i++) {
    const messageEncrypted = req.user.messages[i];
    decryptMessage(messageEncrypted, (decryptedMessage) => {
      console.log('Mensagem Decifrada:', decryptedMessage);
      messagesDecrypted.push(decryptedMessage);
    });
  }
  console.log(req.user)
  User.find({})
  .then(function(users){
    if (users){
      res.render("users", { users, messagesDecrypted })
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
  console.log("---------------------------")
  console.log(req.user)
  console.log("---------------------------")
  encryptMessage(message, req.user.cellphone, req.user.salt, (encryptedMessage) => {
    console.log('Mensagem Criptografada:', encryptedMessage.content);
    console.log("salt")
    console.log(req.user.salt)
    console.log("cellphone")
    console.log(req.user.cellphone)
    sendMessage(encryptedMessage, username)
  });

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
    res.redirect('/qrcode');
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

// Função para derivar a chave usando PBKDF2
function deriveKey(cellphone, salt, callback) {
  const iterations = 10000;
  const keyLength = 32; // Tamanho da chave em bytes

  crypto.pbkdf2(cellphone, salt, iterations, keyLength, 'sha256', (err, key) => {
    if (err) throw err;
    callback(key);
  });
}

// Função para criptografar uma mensagem
function encryptMessage(message, cellphone, salt, callback) {
  deriveKey(cellphone, salt, (key) => {
    const iv = crypto.randomBytes(16); // Gera um IV aleatório de 16 bytes
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(message, 'utf-8', 'hex');
    encrypted += cipher.final('hex');

    const encryptedMessage = {content: iv.toString('hex') + encrypted, tag: cellphone, salt};
    callback(encryptedMessage);
  });
}

// Função para descriptografar uma mensagem
function decryptMessage(encryptedMessage, callback) {
  deriveKey(encryptedMessage.tag, encryptedMessage.salt, (key) => {
    const iv = encryptedMessage.content.slice(0, 16); // Assume que o IV está nos primeiros 16 bytes
    const encryptedData = encryptedMessage.content;

    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf-8');
    console.log(decrypted)
    decrypted = decipher.final('utf-8');

    callback(decrypted);
  });
}
