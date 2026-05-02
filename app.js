require("./utils.js");
require("dotenv").config();
const port = process.env.PORT || 3000;
const expireTime = 1 * 60 * 60 * 1000;

/* Constant requirements */
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const app = express();
const saltRounds = 12;

/* Secretes */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
console.log("Session DB:", mongodb_session_database);

const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

/* Database Connection Connection */
const { database } = include("databaseConnection");
const userCollection = database.db(mongodb_user_database).collection("users");

/* Middleware */

//When set to false, includes built in query string parsing middleware
app.use(express.urlencoded({ extended: false }));

app.use(express.json());

app.use(express.static(__dirname + "/public"));

//Creates a new MongoDB session to store
var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/`,
  dbName: mongodb_session_database,
  collectionName: "sessions",
  autoRemove: "disabled",
});

mongoStore.on("error", function (error) {
  console.log("Session store error:", error);
});

//Validates the session cookie and checks if the user is logged in
app.use(
  session({
    secret: process.env.NODE_SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    store: mongoStore,
    cookie: { maxAge: expireTime },
  }),
);

/* Routes */

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});

app.get("/", (req, res) => {
  if (!req.session.name) {
    res.send(` <h1>Welcome!</h1>
        <button><a href= "/signup">Signup</a></button>
        <button><a href="/login">Login</a></button>`);
  } else {
    res.send(`<h1>Hello, ${req.session.name}!</h1>
    <a href="/members">Go to Members Area</a><br>
    <a href="/logout">Sign Out</a>`);
  }
});

// Signup GET route
app.get("/signup", (req, res) => {
  res.send(`<h1>Create user</h1>
  <form method="post" action="/signup">
    <input type="text" name="name" placeholder="Name" required>
    <input type="email" name="email" placeholder="Email" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Sign Up</button>
  </form>`);
});

//Signup POST route
app.post("/signup", async (req, res) => {
  const name = req.body.name;
  const email = req.body.email;
  const password = req.body.password;

  if (!name) {
    return res.send(
      `<p>Please provide a name.</p><a href="/signup">Try again</a>`,
    );
  }
  if (!email) {
    return res.send(
      `<p>Please provide an email address.</p><a href="/signup">Try again</a>`,
    );
  }
  if (!password) {
    return res.send(
      `<p>Please provide a password.</p><a href="/signup">Try again</a>`,
    );
  }

  //Checks if email exists
  const schema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  // Validate the input against the schema
  const validationResult = schema.validate({ name, email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    return res.send(`<p>Invalid input.</p><a href="/signup">Try again</a>`);
  }

  // Hashes the password and inserts the user into the database
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({ name, email, password: hashedPassword });
  console.log("Inserted user");

  req.session.name = name;
  req.session.cookie.maxAge = expireTime;
  req.session.save(() => {
    res.redirect("/members");
  });
});

// Login GET route
app.get("/login", (req, res) => {
  res.send(
    `<h1>Log In</h1>
    <form action='/login' method='post'>
     <input name='email'    type='text'     placeholder='Email'    /><br>
     <input name='password' type='password' placeholder='Password' /><br>
     <button>Log In</button>
    </form>
    `,
  );
});

// Login POST
app.post("/login", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ email, password });
  if (validationResult.error != null) {
    return res.send(
      `<p>Invalid email or password format.</p><a href="/login">Try again</a>`,
    );
  }

  const result = await userCollection
    .find({ email })
    .project({ name: 1, email: 1, password: 1, _id: 1 })
    .toArray();

  if (result.length != 1) {
    return res.send(
      `<p>User and password not found.</p><a href="/login">Try again</a>`,
    );
  }

  if (await bcrypt.compare(password, result[0].password)) {
    req.session.name = result[0].name;
    req.session.cookie.maxAge = expireTime;
    req.session.save(() => {
      return res.redirect("/members");
    });
  } else {
    return res.send(
      `<p>User and password not found.</p><a href="/login">Try again</a>`,
    );
  }
});

// Members
app.get("/members", async (req, res) => {
  const schema = Joi.object({
    sessions: Joi.string().required(),
  });
  const validationResult = schema.validate({ sessions: req.session });
  if (validationResult.error != null) {
    return res.send(`<p>Invalid session.</p><a href="/login">Log in</a>`);
  }
  const hashedSession = await bcrypt.hash(req.session.sessions, saltRounds);
  await sessionCollection.insertOne({ _id, expires, session: hashedSession });

  console.log("Session data:", req.session);
  console.log("Session name:", req.session.name);

  if (!req.session.name) {
    res.redirect("/");
    return;
  }

  const images = ["flower.jpg", "minions.jpg", "sunchips.jpg"];
  const randomImage = images[Math.floor(Math.random() * images.length)];

  res.send(`
    <h1>Hello, ${req.session.name}!</h1>
    <img src="/${randomImage}" style="width:400px;" /><br><br>
    <a href="/logout">Sign Out</a>
`);
});

//logs out user
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

//404 route
app.use((req, res) => {
  res.status(404).send("Page not found");
});
