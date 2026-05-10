require("./utils.js");
require("dotenv").config();

/* Constants */
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const crypto = require("crypto");
const path = require("path");

const app = express();
const port = process.env.PORT || 3000;
const expireTime = 1 * 60 * 60 * 1000; // 1 hour
const saltRounds = 12;

/*  Secrets  */
const {
  MONGODB_HOST: mongodb_host,
  MONGODB_USER: mongodb_user,
  MONGODB_PASSWORD: mongodb_password,
  MONGODB_USER_DATABASE: mongodb_user_database,
  MONGODB_SESSION_DATABASE: mongodb_session_database,
  MONGODB_SESSION_SECRET: mongodb_session_secret,
  NODE_SESSION_SECRET: node_session_secret,
} = process.env;

/*  Navigation  */
const navLinks = [
  { name: "Home", url: "/" },
  { name: "Members", url: "/members" },
  { name: "Admin", url: "/admin" },
  { name: "Login", url: "/login" },
  { name: "Sign Up", url: "/signup" },
];

/*  Encryption  */
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

/*  Database  */
const { database } = include("databaseConnection");
const userCollection = database.db(mongodb_user_database).collection("users");

/*  Middleware  */
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Session Store  
var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/`,
  dbName: mongodb_session_database,
  collectionName: "sessions",
  autoRemove: "disabled",
  serialize: (session) => ({ data: encrypt(JSON.stringify(session)) }),
  unserialize: (session) => {
    if (session.data) {
      const decrypted = decrypt(session.data);
      if (decrypted) return JSON.parse(decrypted);
    }
    return session;
  },
});

mongoStore.on("error", (error) => console.log("Session store error:", error));

app.use(
  session({
    secret: node_session_secret,
    resave: true,
    saveUninitialized: false,
    store: mongoStore,
    cookie: { maxAge: expireTime },
  })
);

// render with nav  
function renderPage(res, page, extras = {}) {
  res.render(page, { navItems: navLinks, ...extras });
}

// Joi Schemas  
const signupSchema = Joi.object({
  name: Joi.string().max(50).required(),
  email: Joi.string().email().required(),
  password: Joi.string().max(20).required(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().max(20).required(),
});

const emailSchema = Joi.object({
  email: Joi.string().email().required(),
});

/* Server */
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

/*  Routes  */

// Home
app.get("/", (req, res) => {
  renderPage(res, "index", { name: req.session.name || null, currentPage: "/" });
});

// Signup GET
app.get("/signup", (req, res) => {
  renderPage(res, "signup", { error: null });
});

// Signup POST
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name) return renderPage(res, "signup", { error: "Please provide a name.", currentPage: "/signup" });
  if (!email) return renderPage(res, "signup", { error: "Please provide an email address.", currentPage: "/signup" });
  if (!password) return renderPage(res, "signup", { error: "Please provide a password.", currentPage: "/signup" });

  const { error } = signupSchema.validate({ name, email, password });
  if (error) return renderPage(res, "signup", { error: "Invalid input.", currentPage: "/signup" });

  const hashedPassword = await bcrypt.hash(password, saltRounds);

  //Automatically assign admin if email is admin@email.com
  const user_type = email === "admin@email.com" ? "admin" : "user";

  await userCollection.insertOne({ name, email, password: hashedPassword, user_type });

  req.session.name = name;
  req.session.email = email;
  req.session.user_type = user_type;
  req.session.cookie.maxAge = expireTime;
  req.session.save(() => res.redirect("/members"));
});


// Login GET
app.get("/login", (req, res) => {
  renderPage(res, "login", { error: null, currentPage: "/login" });
});

// Login POST
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  // Joi validation
  const { error } = loginSchema.validate({ email, password });
  if (error) return renderPage(res, "login", { error: "Invalid email or password format.", currentPage: "/login" });

  // Find user
  const result = await userCollection
    .find({ email })
    .project({ name: 1, email: 1, password: 1, user_type: 1, _id: 1 })
    .toArray();

  if (result.length !== 1) {
    return renderPage(res, "login", { error: "User and password not found.", currentPage: "/login" });
  }

  // Check password
  const user = result[0];
  if (await bcrypt.compare(password, user.password)) {
    req.session.name = user.name;
    req.session.email = user.email;
    req.session.user_type = user.user_type;
    req.session.cookie.maxAge = expireTime;
    req.session.save(() => res.redirect("/members"));
  } else {
    return renderPage(res, "login", { error: "User and password not found.", currentPage: "/login" });
  }
});

// Members
app.get("/members", (req, res) => {
  if (!req.session.name) return res.redirect("/");
  renderPage(res, "members", { name: req.session.name, currentPage: "/members" });
});

// Admin
app.get("/admin", async (req, res) => {
  if (!req.session.name) return res.redirect("/");
  if (req.session.user_type !== "admin") {
    return res.status(403).render("403", { 
      navItems: navLinks,
      currentPage: "/admin" 
    });
  }
  const users = await userCollection.find().toArray();
  renderPage(res, "admin", { users, currentPage: "/admin" });
});


// Promote user
app.get("/promoteUser", async (req, res) => {
  const { error } = emailSchema.validate({ email: req.query.email });
  if (error) return res.status(400).render("404", { navItems: navLinks });
  await userCollection.updateOne({ email: req.query.email }, { $set: { user_type: "admin" } });
  res.redirect("/admin");
});

// Demote user
app.get("/demoteUser", async (req, res) => {
  const { error } = emailSchema.validate({ email: req.query.email });
  if (error) return res.status(400).render("404", { navItems: navLinks });
  await userCollection.updateOne({ email: req.query.email }, { $set: { user_type: "user" } });
  res.redirect("/admin");
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// 404
app.use((req, res) => {
  res.status(404).render("404", { navItems: navLinks });
});