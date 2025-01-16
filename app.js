const express = require("express");
const session = require("express-session");
const passport = require("passport");
const routes = require("./routes");
const pg = require("pg");
const pgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcryptjs");
const pool = require("./db/pool");
const PORT = process.env.PORT;
require("./config/passport");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const sessionStore = new pgSession({
  pool: pool,
});

app.use(
  session({
    store: sessionStore,
    secret: process.env.secret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());
app.use(routes);
app.listen(PORT, () => console.log(`app listening on port: ${PORT}`));
