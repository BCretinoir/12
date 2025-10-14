const mysql = require("mysql");
const bcrypt = require("bcrypt");
const path = require("path");
const fs = require("fs");

const DB_PATH = path.join(__dirname, "..", "data", "app.db");
if (!fs.existsSync(path.join(__dirname, "..", "data")))
  fs.mkdirSync(path.join(__dirname, "..", "data"));
const sql = fs.readFileSync(path.join(__dirname, "init_db.sql"), "utf8");

var db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "",
  multipleStatements: true, 
});

db.connect(function (err) {
  if (err) {
    console.error("error connecting: " + err.stack);
    return;
  }
  console.log("connected as id " + db.threadId);
});

db.query(sql, (err) => {
  if (err) {
    console.error(err);
    process.exit(1);
  }
  const hash = bcrypt.hashSync("teacherpass", 10);
  db.query(
    "UPDATE users SET password_hash = ? WHERE username = 'teacher'",
    [hash],
    (e) => {
      if (e) console.error(e);
      else console.log("DB initialized with users and posts.");
      db.end();
    }
  );
});
