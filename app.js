// app.js
const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");
const engine = require("ejs-locals");
const connexion = require("mysql");
const { initSecurity } = require("./app.secure");

const app = express();

app.engine("ejs", engine);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));

// --- MySQL connection ---
const db = connexion.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "my_db",
  multipleStatements: true,
});
db.connect((err) => {
  if (err) {
    console.error(err);
    process.exit(1);
  }
  console.log("MySQL connected");
});

// --- Init security ---
const secure = initSecurity(app, db);
const profileRoutes = require("./profile.routes")(db, secure);
app.use("/profile", profileRoutes);

// --- Locals middleware ---
app.use((req, res, next) => {
  res.locals.user = req.session?.username || null;
  res.locals.userIsAdmin = req.session?.isAdmin === true;
  next();
});

// --- Routes ---

// Home
app.get("/", (req, res) => {
  db.query(
    "SELECT id, title, body FROM posts ORDER BY id DESC LIMIT 50",
    (err, rows) => {
      if (err) return res.status(500).send("DB error");
      res.render("index", { posts: rows });
    }
  );
});

// Login
app.get("/login", (req, res) => {
  res.render("login", { message: null });
});

app.post("/login", secure.loginLimiter, async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  db.query(
    "SELECT id, username, password_plain, password_hash FROM users WHERE username = ? LIMIT 1",
    [username],
    async (err, results) => {
      if (err) return res.status(500).send("DB error");
      if (!results || results.length === 0)
        return res.render("login", { message: "Invalid credentials" });

      const row = results[0];

      try {
        if (row.password_plain && row.password_plain === password) {
          await secure.migratePasswordOnLogin(row, password);
        } else if (
          row.password_hash &&
          (await bcrypt.compare(password, row.password_hash))
        ) {
          // OK
        } else {
          return res.render("login", { message: "Invalid credentials" });
        }

        req.session.userId = row.id;
        req.session.username = row.username;
        req.session.isAdmin = row.username === "admin";
        await secure.logAction(db, req, "login");
        res.redirect("/");
      } catch (e) {
        console.error(e);
        res.status(500).send("Server error");
      }
    }
  );
});

// Logout
app.post("/logout", async (req, res) => {
  await secure
    .logAction(db, req, "logout", "User logged out")
    .catch(console.error);
  req.session.destroy((err) => {
    if (err) console.error(err);
    res.redirect("/");
  });
});

// Create post
app.get("/post", secure.requireAuth, (req, res) => {
  res.render("post");
});
app.post("/post", secure.requireAuth, async (req, res) => {
  const title = String(req.body.title || "").trim();
  const body = secure.sanitizeHtml(req.body.body || "");

  try {
    await new Promise((resolve, reject) => {
      db.query(
        "INSERT INTO posts (title, body) VALUES (?, ?)",
        [title, body],
        (err) => (err ? reject(err) : resolve())
      );
    });
    await secure.logAction(db, req, "post_create", `Title: ${title}`);
    req.session.save((err) => {
      if (err) console.error(err);
      res.redirect("/");
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("DB error");
  }
});

// Reset DB
app.get("/reset-db", secure.requireAuth, secure.protectResetDb, (req, res) => {
  const init = fs.readFileSync(
    path.join(__dirname, "scripts", "init_db.sql"),
    "utf8"
  );
  db.query(init, (err) => {
    if (err) return res.status(500).send("DB init error");
    res.send('DB reset done. <a href="/">Home</a>');
  });
});

app.get("/register", (req, res) => {
  res.render("register", { message: null });
});

// POST /register
app.post("/register", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (!username || !password) {
    return res.render("register", {
      message: "Username and password are required",
    });
  }

  try {
    db.query(
      "SELECT id FROM users WHERE username = ? LIMIT 1",
      [username],
      async (err, results) => {
        if (err) return res.status(500).send("DB error");
        if (results.length > 0) {
          return res.render("register", { message: "Username already exists" });
        }

        // Hash du mot de passe
        const hash = await bcrypt.hash(password, secure.saltRounds || 12);

        // Insert dans la DB
        db.query(
          "INSERT INTO users (username, password_hash) VALUES (?, ?)",
          [username, hash],
          (err) => {
            if (err) return res.status(500).send("DB error");
            res.redirect("/login");
          }
        );
      }
    );
  } catch (e) {
    console.error("Register error:", e);
    res.status(500).send("Server error");
  }
});

// --- Start server ---
const PORT = process.env.PORT || 4000;
app.listen(PORT, "127.0.0.1", () =>
  console.log(`App listening on http://127.0.0.1:${PORT}`)
);
