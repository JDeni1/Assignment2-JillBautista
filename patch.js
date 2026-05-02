const fs = require("fs");
const path = "./node_modules/connect-mongo/build/main/lib/MongoStore.js";

try {
  let content = fs.readFileSync(path, "utf8");

  if (content.includes("if (existingIndex.length")) {
    content = content.replace(
      "if (existingIndex.length",
      "if (existingIndex && existingIndex.length",
    );
    fs.writeFileSync(path, content);
    console.log("connect-mongo patched successfully");
  } else {
    console.log("Patch already applied or not needed");
  }
} catch (err) {
  console.error("Patch failed:", err);
}
