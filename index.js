const express = require('express');
const axios = require('axios');
const passport = require('passport');
const session = require('express-session');
const Auth0Strategy = require('passport-auth0');
const ejs = require('ejs');
const path = require('path');
const cookieParser = require('cookie-parser');
const app = express();

app.set('view engine', 'ejs'); // Set EJS as the template engine
app.set("views",path.join(__dirname,"./views"));;

const config = {
    clientID: 'zz8J0DCF3tD8vUVNiBpKqu5u3xtO1vYg',
    clientSecret: 'xl8D_ggiFek6o7L3BFW7DtxlOVBm0D1KIuABxanMvG6cL2uTsFvuKCrkM9T5biOa',
    audience: 'https://dev-npofkt2fait2dmyy.us.auth0.com/api/v2/', // API identifier for the protected resource
    tokenURL: 'https://dev-npofkt2fait2dmyy.us.auth0.com/oauth/token',
  };

app.use(session({
    secret: 'your-session-secret', // Change this to a random string
    resave: true,
    saveUninitialized: true,
    cookie: {
      maxAge: 60*100, // Set the cookie to expire immediately
      httpOnly: true, // Ensures the cookie is only accessed through HTTP requests
    }
  }));
  
app.use(passport.initialize());
app.use(passport.session());
app.use(cookieParser());

passport.use(new Auth0Strategy({
    domain: 'dev-npofkt2fait2dmyy.us.auth0.com',
    clientID: 'zz8J0DCF3tD8vUVNiBpKqu5u3xtO1vYg',
    clientSecret: 'xl8D_ggiFek6o7L3BFW7DtxlOVBm0D1KIuABxanMvG6cL2uTsFvuKCrkM9T5biOa',
    callbackURL: 'https://rpaccessmanagementfoundationlabproxy.onrender.com/callback',
    logoutUrl:'https://rpaccessmanagementfoundationlabproxy.onrender.com/'
  },
  function(accessToken, refreshToken, extraParams, profile, done) {
    // Store user information in session or database
    return done(null, profile);
  }
));

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});


app.get('/get-token', (req, res) => {
    axios.post(config.tokenURL, {
      client_id: config.clientID,
      client_secret: config.clientSecret,
      audience: config.audience,
      grant_type: 'client_credentials',
    })
    .then(response => {
      const accessToken = response.data.access_token;
      // Store the access token securely, like in a session or environment variable
      res.send(`Access Token: ${accessToken}`);
    })
    .catch(error => {
      console.error(error);
      res.status(500).send('Error obtaining access token');
    });
});

app.get('/protected-resource', (req, res) => {
    const accessToken = req.headers.authorization;
  
    if (!accessToken) {
      return res.status(401).send('Unauthorized');
    }
    
    // Use the access token to make a request to the protected resource
    axios.get('http://localhost:3000/protected-resource', {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    })
    .then(response => {
      // Handle the response from the protected resource
      res.send(response.data);
    })
    .catch(error => {
      console.error(error);
      res.status(500).send('Error accessing protected resource');
    });
  });

  // Login route
app.get('/login', passport.authenticate('auth0', {
  scope: 'openid email profile'
}));

// Callback route after successful authentication
app.get('/callback', passport.authenticate('auth0', {
  failureRedirect: '/login'
}), (req, res) => {
  // Successful authentication, redirect to the home page or another protected route
  
  res.redirect('https://rpaccessmanagementfoundationlabproxy.onrender.com/');
});

// Home route
app.get('/', (req, res) => {
  // Check if the user is authenticated
  if (req.isAuthenticated()) {
    // User is authenticated, proceed with rendering the content
    const username = req.user.displayName; // User data is stored in req.user after authentication
    res.render('index', { username });
  } else {
    // User is not authenticated, redirect to the login page
    res.redirect('https://rpaccessmanagementfoundationlabproxy.onrender.com/login');
  }
});

  
  
  app.get('/logout', (req, res) => {
      req.session.destroy((err) => {
        if (err) {
          console.error('Error destroying session:', err);
        }
        // Clear any cookies related to authentication
        res.clearCookie('connect.sid');
        // Redirect the user to the desired page after logout
        res.redirect("https://dev-npofkt2fait2dmyy.us.auth0.com/v2/logout?returnTo=https://rpaccessmanagementfoundationlabproxy.onrender.com/&client_id=zz8J0DCF3tD8vUVNiBpKqu5u3xtO1vYg");
      });
    });
  

const port = 3000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
