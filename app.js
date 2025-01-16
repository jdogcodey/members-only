const express = require("express");
const session = require("express-session");
const passport = require("passport");
const routes = require("./routes");
const pg = require("pg");
const pgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcryptjs");

const app = express();
