const express = require('express');
const mongoose = require('mongoose');
const sessions = require('client-sessions');
const bcrypt = require('bcryptjs');
const csrf = require('csurf');
const helmet = require('helmet');

const DB_OPTIONS = {
  useNewUrlParser: true,
  useUnifiedTopology: true
};

mongoose.connect('mongodb://localhost/ss-auth', DB_OPTIONS);
mongoose.connection.once('open', () => {
  console.log('conneted to database');
});

let User = mongoose.model(
  'User',
  new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
  })
);

const app = express();

app.use(express.urlencoded({ extended: false }));
app.set('view engine', 'pug');

app.use(
  sessions({
    cookieName: 'session',
    secret: 'averysecuresecret',
    duration: 30 * 60 * 1000,
    httpOnly: true,
    secure: true // set cookies only over https
    // ephemeral: true // desroys cookies when browser closes
  })
);

app.use((req, res, next) => {
  if (!(req.session && req.session.userId)) {
    return next();
  }

  User.findById(req.session.userId, (err, user) => {
    if (err) {
      return next(err);
    }

    if (!user) {
      return next();
    }

    user.password = undefined;

    req.user = user;
    res.locals.user = user;

    next();
  });
});

// app.use(csrf());
app.use(helmet());

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', (req, res) => {
  let hash = bcrypt.hashSync(req.body.password, 14);
  req.body.password = hash;

  let user = new User(req.body);

  user.save(err => {
    let error;
    if (err) {
      error = 'Something went wrong';

      if (err.code === 11000) {
        error = 'That email is already taken, Please try another';
      }
      return res.render('register', { error: error });
    }

    res.redirect('/dashboard');
  });
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', (req, res) => {
  User.findOne({ email: req.body.email }, (err, user) => {
    if (err || !user || !bcrypt.compareSync(req.body.password, user.password)) {
      return res.render('login', { error: 'Incorrect email / password' });
    }

    req.session.userId = user._id;
    res.redirect('/dashboard');
  });
});

function loginRequired(req, res, next) {
  if (!req.user) {
    return res.redirect('/login');
  }

  next();
}

app.get('/dashboard', loginRequired, (req, res, next) => {
  // if (!(req.session && req.session.userId)) {
  //   return res.redirect('/login');
  // }

  // User.findById(req.session.userId, (err, user) => {
  //   if (err) {
  //     return next(err);
  //   }

  //   if (!user) {
  //     return res.redirect('/login');
  //   }

  res.render('dashboard');
  // });
});

app.listen(2020, () => {
  console.log('server up @ 2020');
});
