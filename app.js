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
const path = require("path");
const app = express();
const saltRounds = 12;

//Navigation links for header
const navLinks = [ { name: "Home", url: "/" }, 
{ name: "Members", url: "/members" }, 
{ name: "Admin", url: "/admin" },
{ name: "404", url: "/404" },];

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

/* EJS connection */
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

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
  res.render("index", { name: req.session.name || null }, { navItems: navLinks });
});

// Signup GET
app.get("/signup", (req, res) => {
  res.render("signup", { error: null });
});

app.post("/signup", async (req, res) => {
  const name = req.body.name;
  const email = req.body.email;
  const password = req.body.password;
  if (!name) return res.render("signup", { error: "Please provide a name." });
  if (!email)
    return res.render("signup", { error: "Please provide an email address." });
  if (!password)
    return res.render("signup", { error: "Please provide a password." });
  const schema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });
  const validationResult = schema.validate({ name, email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    return res.render("signup", { error: "Invalid input." });
  }
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({
    name,
    email,
    password: hashedPassword,
    user_type: "user", // added user_type
  });
  console.log("Inserted user");
  req.session.name = name;
  req.session.email = email;
  req.session.user_type = "user";
  req.session.cookie.maxAge = expireTime;
  req.session.save(() => {
    res.redirect("/members");
  });
});

// Login GET
app.get("/login", (req, res) => {
  res.render("login", { error: null });
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
    return res.render("login", { error: "Invalid email or password format." });
  }

  const result = await userCollection
    .find({ email })
    .project({ name: 1, email: 1, password: 1, user_type: 1, _id: 1 })
    .toArray();

  if (result.length != 1) {
    return res.render("login", { error: "User and password not found." });
  }

  if (await bcrypt.compare(password, result[0].password)) {
    req.session.name = result[0].name;
    req.session.email = result[0].email;
    req.session.user_type = result[0].user_type;
    req.session.cookie.maxAge = expireTime;
    req.session.save(() => {
      return res.redirect("/members");
    });
  } else {
    return res.render("login", { error: "User and password not found." });
  }
});

// Members
app.get("/members", (req, res) => {
  if (!req.session.name) {
    res.redirect("/");
    return;
  }
  res.render("members", { name: req.session.name });
});

app.get("/admin", async (req, res) => {
  if (!req.session.name) {
    return res.redirect("/login");
  }
  if (req.session.user_type !== "admin") {
    return res.status(403).render("403");
  }
  const users = await userCollection.find().toArray();
  res.render("admin", { users });
});

// Promote user
app.get("/promoteUser", async (req, res) => {
  const email = req.query.email;

  const schema = Joi.object({ email: Joi.string().email().required() });
  const { error } = schema.validate({ email });
  if (error) return res.status(400).render("404");

  await userCollection.updateOne({ email }, { $set: { user_type: "admin" } });
  res.redirect("/admin");
});

// Demote user
app.get("/demoteUser", async (req, res) => {
  const email = req.query.email;

  const schema = Joi.object({ email: Joi.string().email().required() });
  const { error } = schema.validate({ email });
  if (error) return res.status(400).render("404");

  await userCollection.updateOne({ email }, { $set: { user_type: "user" } });
  res.redirect("/admin");
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// 404
app.use((req, res) => {
  res.status(404).render("404");
});
