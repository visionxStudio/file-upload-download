const path = require('path');
const chalk = require('chalk');
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(session);
const csrf = require('csurf');
const flash = require('connect-flash');
const multer = require('multer');

const errorController = require('./controllers/error');
const User = require('./models/user');

const MONGODB_URI =
  'mongodb+srv://manish:iamvisionx123@test-42wxh.mongodb.net/shop';

const app = express();

// initializing the session store for storing the session in the database
const store = new MongoDBStore({
  uri: MONGODB_URI,
  collection: 'sessions' // this will store the session in the collection named sessions
});

// initializing the csrf protection
const csrfProtection = csrf();

// setting up the file storage for the images (destination and the filename)
const fileStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'images');
  },
  filename: (req, file, cb) => {
    cb(null, new Date().toISOString() + '-' + file.originalname);
  }
});

// filtering by mimetypes
const fileFilter = (req, file, cb) => {
  if (file.mimetype === 'image/png' || file.mimetype === 'image/jpg' || file.mimetype === 'image/jpeg') {
    cb(null, true);
  } else {
    cb(null, false);
  }
};

app.set('view engine', 'ejs');
app.set('views', 'views');

const adminRoutes = require('./routes/admin');
const shopRoutes = require('./routes/shop');
const authRoutes = require('./routes/auth');

app.use(bodyParser.urlencoded({
  extended: false
}));

app.use(multer({
  storage: fileStorage,
  fileFilter: fileFilter
}).single('image'));

app.use(express.static(path.join(__dirname, 'public')));
/* 
  Here we are specifying that the /image is for the url and images is for directory
*/
app.use('/images', express.static(path.join(__dirname, 'images')));



app.use(
  session({
    secret: 'my secret',
    resave: false,
    saveUninitialized: false,
    store: store // store this in the store that is initialized above
  })
);

app.use(csrfProtection);

app.use(flash());

app.use((req, res, next) => {
  if (!req.session.user) {
    return next();
  }
  User.findById(req.session.user._id)
    .then(user => {
      if (!user) {
        return next();
      }
      req.user = user;
      next();
    })
    .catch(err => {
      throw new Error(err);
    });
});


// storing isAuthenticated and csrfToken in locals
app.use((req, res, next) => {
  res.locals.isAuthenticated = req.session.isLoggedIn; // res.locals stores the data and nakes it available in the views
  res.locals.csrfToken = req.csrfToken();
  next();
});

app.use('/admin', adminRoutes);
app.use(shopRoutes);
app.use(authRoutes);

app.get('/500', errorController.get500);

app.use(errorController.get404);

mongoose
  .connect(
    MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    }, // checking for the errors
    (err) => {
      if (err) {
        console.log(chalk.inverse.red(err));
      } else {
        console.log(chalk.greenBright.inverse.bold("Connected!"));
      }
    })
  .then(result => {
    app.listen(3000);
  })
  .catch(err => {
    console.log(err);
  });