const router = require("express").Router();
const passport = require("passport");
const bcrypt = require("bcryptjs");
const pool = require("../db/pool");
const { body, validationResult } = require("express-validator");
require("dotenv").config();

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/log-in");
}

function ensureMember(req, res, next) {
  if (req.user.membership_status === true) {
    return next();
  }
  res.redirect("/membership");
}

router.get("/", (req, res) => res.render("index", { user: req.user }));

router.get("/sign-up", (req, res) =>
  res.render("sign-up-form", { user: req.user })
);

router.get("/membership", ensureAuthenticated, (req, res, next) => {
  res.render("membership", { user: req.user, incorrectLogin: false });
});

router.get("/log-in", (req, res) => res.render("log-in", { user: req.user }));

router.post(
  "/sign-up",
  [
    body("first_name")
      .trim()
      .notEmpty()
      .withMessage("First name is required")
      .isAlpha()
      .withMessage("First name must only contain letters"),
    body("last_name")
      .trim()
      .notEmpty()
      .withMessage("Last name is required")
      .isAlpha()
      .withMessage("Last name must only contain letters"),
    body("username").trim().notEmpty().withMessage("Username is required"),
    body("email")
      .trim()
      .isEmail()
      .withMessage("Must be a valid email")
      .normalizeEmail(),
    body("password")
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters long")
      .matches(/[A-Z]/)
      .withMessage("Password must contain at least one uppercase letter")
      .matches(/[a-z]/)
      .withMessage("Password must contain at least one lowercase letter")
      .matches(/[0-9]/)
      .withMessage("Password must contain at least one number")
      .matches(/[@$!%*?&]/)
      .withMessage(
        "Password must contain at least one special character (@$!%*?&)"
      )
      .not()
      .isIn(["password", "123456", "qwerty"])
      .withMessage("Password is too common")
      .trim()
      .escape(),
    body("confirm-password").custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("Password confirmation does not match password");
      }
      return true;
    }),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    try {
      const { rows } = await pool.query(
        "SELECT * FROM users WHERE email = $1 OR username = $2",
        [req.body.email, req.body.username]
      );
      if (rows.length > 0) {
        const duplicateField =
          rows[0].email === req.body.email ? "email" : "username";
        return res.status(400).json({
          errors: [
            {
              msg: `${duplicateField} is already in use`,
              param: duplicateField,
            },
          ],
        });
      }

      const hashedPassword = await bcrypt.hash(req.body.password, 10);

      await pool.query(
        "INSERT INTO users (first_name, last_name, username, email, password ) VALUES ($1, $2, $3, $4, $5)",
        [
          req.body.first_name,
          req.body.last_name,
          req.body.username,
          req.body.email,
          hashedPassword,
        ]
      );
      res.redirect("/");
    } catch (err) {
      next(err);
    }
  }
);

router.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/log-in",
    failureMessage: true,
  })
);

router.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/log-in");
  });
});

router.post("/membership", (req, res, next) => {
  if (req.body.secret === process.env.USER_SECRET) {
    pool.query("UPDATE users SET membership_status = true WHERE id = $1", [
      req.user.id,
    ]);
    res.redirect("/membership");
  } else {
    res.render("membership", { user: req.user, incorrectLogin: true });
  }
});

router.post("/lose-membership", (req, res, next) => {
  pool.query("UPDATE users SET membership_status = false WHERE id = $1", [
    req.user.id,
  ]);
  res.redirect("/membership");
});

router.get(
  "/create-post",
  ensureAuthenticated,
  ensureMember,
  (req, res, next) => {
    res.render("new-post", { user: req.user });
  }
);

module.exports = router;
