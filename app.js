const app = express();
const port = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000; // 1 hour (Change to one day)

/* Constant requirements */
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const saltRounds = 12;

/* Middleware */
app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: new MongoStore({ url: process.env.MONGODB_URI }),
  }),
);

app.get("/", (req, res) => {
  res.send("Hello, World!");
});

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
