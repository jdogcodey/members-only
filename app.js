const path = require("node:path");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const routes = require("./routes");
const pg = require("pg");
const pgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcryptjs");
const LocalStrategy = require("passport-local").Strategy;
const { body, validationResult } = require("express-validator");
const pool = require("./db/pool");
require("dotenv").config();
const PORT = process.env.PORT;
require("./config/passport");

const app = express();
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const sessionStore = new pgSession({
  pool: pool,
});

app.use(
  session({
    store: sessionStore,
    secret: process.env.SECRET,
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
