// set up server and dependencies
const express = require('express');
const morgan = require('morgan');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const port = 3000;

// placeholder for registration data - username and hashed password
const users = [];

// set up view engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// set up middleware
app.use(morgan('common'));
app.use(express.static('public_html'));
app.use(express.urlencoded({ extended: true }));

app.use(session({                   // options to configure session behaviour
    secret: 'your_secret_key',      // key for the server knows a session cookie is genuine
    resave: false,                  // only modified sessions are saved
    saveUninitialized: false,       // no empty sessions
    cookie: {
        httpOnly: true,             // so JS can’t read it
        secure: false,              // for local development set to false so cookie is sent over both http and https, otherwise never reach server
        maxAge: 60 * 60 * 1000      // 1 hr session timeout, once the cookie expires the user must log in again
    }
}));

// this function is to protect route /login 
function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login');
    } else {
        next();
    }
}

// routes

// home page
app.get('/home', (req,res)=> {
    res.render('home', {user: null})
})

// show dashboard if login else home 
app.get('/', (req, res) => {
    if (req.session.user) {
        res.redirect('/dashboard')
    } else {
        res.redirect('/home')
    }
});

// registration
app.get('/register', (req, res) => {
    res.render('register',{user: null})
})

app.post('/register', async (req, res) => {         // this function always return promise 
    const username = req.body.username;
    const password = req.body.password;
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds); // wait here until promise come back

    users.push({ username, hashedPassword });

    console.log(users);

    res.send(`<h2>Thank you, registration complete.</h2>
    <br>
    <a href="/login">Back to login</a>
    `
    )
})

// login
app.get('/login', (req, res) => {
    res.render('login', {user: null})
})

app.post('/login', async (req, res) => {
    const username = req.body.username.trim();
    const password = req.body.password;

    const user = users.find(u => u.username === username);                // look for user

    const verified = user && await bcrypt.compare(password, user.hashedPassword);  // user is found and bcrypt compare password matched 

    if (!verified) {
        return res.status(401).send(
            `<h1>Wrong username or password.</h1>
            <a href="/login">Try again</a>`
        );
    }
    req.session.user = { username };         // success login, store the login in the session and go to dashboard
    res.redirect('/dashboard');
})

// logout
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

// protected routes
app.get('/dashboard', requireLogin, (req, res) =>
    res.render('dashboard', { user: req.session.user }));

app.get('/tutorial', requireLogin, (req, res) =>
    res.render('tutorial', { user: req.session.user }));

// start server
app.listen(port, () => {
    console.log(`Web server running at: http://localhost:${port}`)
    console.log(`Type Ctrl+C to shut down the web server`)
})