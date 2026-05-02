require("dotenv").config();

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;

const MongoClient = require("mongodb").MongoClient;
const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${process.env.MONGODB_DB}?retryWrites=true&w=majority`;

console.log(atlasURI);

var database = new MongoClient(atlasURI, {});
async function connectDB() {
  try {
    await database.connect();
    console.log("Connected to MongoDB");
  } catch (err) {
    console.error("DB connection error:", err);
  }
}

connectDB();

module.exports = { database };
