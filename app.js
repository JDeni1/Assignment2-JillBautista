require("./utils.js");
require("dotenv").config();

const port = process.env.PORT || 3000;
const expireTime = 1 * 60 * 60 * 1000; // 1 hour

/* Constant requirements */
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const crypto = require("crypto");
const app = express();
const saltRounds = 12;

/* Secrets */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

/* Encryption helpers using Node.js built-in crypto */
const ENCRYPTION_KEY = crypto.scryptSync(mongodb_session_secret, "salt", 32);
const IV_LENGTH = 16;

function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted;
}

function decrypt(text) {
  try {
    const [ivHex, encrypted] = text.split(":");
    const iv = Buffer.from(ivHex, "hex");
    const decipher = crypto.createDecipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (e) {
    return null;
  }
}

/* Database Connection */
const { database } = include("databaseConnection");
const userCollection = database.db(mongodb_user_database).collection("users");

/* Middleware */
app.use(express.urlencoded({ extended: false }));
app.use(express.static(__dirname + "/public"));

/* Session store */
var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/`,
  dbName: mongodb_session_database,
  collectionName: "sessions",
  autoRemove: "disabled",
  serialize: (session) => {
    // Encrypt the session data before storing
    const sessionStr = JSON.stringify(session);
    return { data: encrypt(sessionStr) };
  },
  unserialize: (session) => {
    // Decrypt the session data when reading
    if (session.data) {
      const decrypted = decrypt(session.data);
      if (decrypted) return JSON.parse(decrypted);
    }
    return session;
  },
});

mongoStore.on("error", function (error) {
  console.log("Session store error:", error);
});

app.use(
  session({
    secret: node_session_secret,
    resave: true,
    saveUninitialized: false,
    store: mongoStore,
    cookie: { maxAge: expireTime },
  }),
);

/* Routes */
app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});

// Home
app.get("/", (req, res) => {
  if (!req.session.name) {
    res.send(`
      <h1>Welcome!</h1>
      <a href="/signup">Sign up</a><br>
      <a href="/login">Log in</a>
    `);
  } else {
    res.send(`
      <h1>Hello, ${req.session.name}!</h1>
      <a href="/members">Go to Members Area</a><br>
      <a href="/logout">Sign Out</a>
    `);
  }
});

// Signup GET
app.get("/signup", (req, res) => {
  res.send(`
    <h1>Create User</h1>
    <form method="post" action="/signup">
      <input type="text" name="name" placeholder="Name" /><br>
      <input type="email" name="email" placeholder="Email" /><br>
      <input type="password" name="password" placeholder="Password" /><br>
      <button type="submit">Sign Up</button>
    </form>
  `);
});

// Signup POST
app.post("/signup", async (req, res) => {
  const name = req.body.name;
  const email = req.body.email;
  const password = req.body.password;

  if (!name)
    return res.send(
      `<p>Please provide a name.</p><a href="/signup">Try again</a>`,
    );
  if (!email)
    return res.send(
      `<p>Please provide an email address.</p><a href="/signup">Try again</a>`,
    );
  if (!password)
    return res.send(
      `<p>Please provide a password.</p><a href="/signup">Try again</a>`,
    );

  const schema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ name, email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    return res.send(`<p>Invalid input.</p><a href="/signup">Try again</a>`);
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({ name, email, password: hashedPassword });
  console.log("Inserted user");

  req.session.name = name;
  req.session.cookie.maxAge = expireTime;
  req.session.save(() => {
    res.redirect("/members");
  });
});

// Login GET
app.get("/login", (req, res) => {
  res.send(`
    <h1>Log In</h1>
    <form action="/login" method="post">
      <input name="email" type="text" placeholder="Email" /><br>
      <input name="password" type="password" placeholder="Password" /><br>
      <button>Log In</button>
    </form>
  `);
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
app.get("/members", (req, res) => {
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

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// 404
app.use((req, res) => {
  res.status(404).send("Page not found - 404");
});
