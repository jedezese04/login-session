const express = require('express')
const app = express()
const session = require('express-session')
const mongoose = require('mongoose')
const MongoStore = require('connect-mongo')
const path = require('path')
const bcrypt = require('bcrypt')
require('dotenv')

// Default setup
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'views'))

// Mongoose
let MONGODB_URL = process.env.DB_URL || 'mongodb://localhost:27017/login-session'
mongoose.connect(MONGODB_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => {
    console.log('Database connect successfully!')
  })
  .catch(err => {
    if(err) throw err
  })

// -mongoose schema
let Schema = mongoose.Schema
let userSchema = Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true
  },
  username: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
})
let User = mongoose.model('users', userSchema)

// Session Store
const store =  MongoStore.create({
  mongoUrl: MONGODB_URL
})

// Session
app.use(
  session({
    secret: "my secret session is cat",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24
    },
    store: store
  })
);

// Routers
// -home route
app.get('/', (req, res) => {
  res.render("home")
})

// -login route
app.get('/login', (req, res) => {
  if(req.session.isLogin) {
    return res.redirect('/content')
  }
  const {error} = req.query
  return res.render('login', {error})
})
app.post('/login', async (req, res) => {
  const {username, password} = req.body

  if(!(username && password)) {
    let errorText = encodeURIComponent('You have to fill every form.')
    return res.redirect('/login' + '?error=' + errorText)
  }

  let user = await User.findOne({username})

  if(user.length === 0) {
    let errorText = encodeURIComponent('There is no this username. Please register first!')
    return res.redirect('/login' + '?error=' + errorText)
  }

  const checkPwd = await bcrypt.compare(password, user.password)
  if(!checkPwd) {
    let errorText = encodeURIComponent('Invalid password. Please try again!')
    return res.redirect('/login' + '?error=' + errorText)
  }

  req.session.isLogin = true
  res.redirect('/content')
})

// -register route
app.get('/register', (req, res) => {
  if(req.session.isLogin) {
    return res.redirect('/content')
  }
  const {error} = req.query
  res.render("register", {error})
})
app.post('/register', async (req, res) => {
  const {name, email, username, password} = req.body
  
  if(!(name && email && username && password)) {
    let errorText = encodeURIComponent('You have to fill every form.')
    return res.redirect('/register' + '?error=' + errorText)
  }
  
  let haveUser = await User.find({$or: [{email}, {username}]})
  if(haveUser.length !== 0) {
    let errorText = encodeURIComponent('This username or email is already exists.')
    return res.redirect('/register' + '?error=' + errorText)
  }

  const hashedPassword = await bcrypt.hash(password, 10)
  const newUser = new User({
    name,
    email,
    username,
    password: hashedPassword
  })
  await newUser.save((err) => {
    if(err) throw err
    console.log('Register finished!')
  })
  res.redirect('/login')
})

// -content route
app.get('/content', (req, res) => {
  if(!req.session.isLogin) {
    let errText = encodeURIComponent('You have to login for read content.')
    return res.redirect('/login' + '?error=' + errText)
  }
  res.render('content')
})

// -logout route
app.get('/logout', (req, res) => {
  req.session.destroy()
  res.redirect('/login')
})

// run server
const PORT = process.env.PORT || 3000
app.listen(PORT, (err) => {
  if (err) throw err
  console.log(`Server is running on port ${PORT}`)
})