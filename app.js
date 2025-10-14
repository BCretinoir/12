// app.js
const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");
const engine = require("ejs-locals");
const xss = require("xss");
const connexion = require("mysql");
const { initSecurity } = require("./app.secure");

const app = express();

app.engine("ejs", engine);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));

// Connexion MySQL
var db = connexion.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "my_db", 
  multipleStatements: true,
});

db.connect((err) => {
  if (err) {
    console.error("Erreur de connexion MySQL:", err);
    process.exit(1);
  } else {
    console.log(" Connexion MySQL OK !");
  }
});

// --- Init security middleware ---
const secure = initSecurity(app, db, {
  sessionSecret: process.env.SESSION_SECRET || "please-change-me",
  sessionsDir: path.join(__dirname, "data"),
  sessionsDbFile: "sessions.mysql",
});

app.use((req, res, next) => {
  res.locals.user = req.session?.username || null;
  res.locals.userIsAdmin = req.session?.isAdmin === true;
  try {
    res.locals.session = req.session || {};
    if (req.csrfToken) {
      res.locals.session.csrfToken = req.csrfToken();
    }
  } catch (err) {
    // Ignore si pas de CSRF sur la route
  }
  next();
});

const escapeHtml = secure.escapeHtml;
const sanitizeHtml = secure.sanitizeHtml;
const loginLimiter = secure.loginLimiter;
const requireAuth = secure.requireAuth;
const protectResetDb = secure.protectResetDb;
const safeRenderMiddleware = secure.safeRenderMiddleware;

// Apply safeRenderMiddleware globally
app.use(safeRenderMiddleware);

// --- ROUTES ---

// Home page
app.get("/", (req, res) => {
  db.query(
    "SELECT id, title, body FROM posts ORDER BY id DESC LIMIT 50",
    (err, rows) => {
      if (err) return res.status(500).send("DB error");
      res.render("index", {
        posts: rows,
        user: req.session.username ? escapeHtml(req.session.username) : null,
        userIsAdmin: req.session.isAdmin === true,
      });
    }
  );
});

// Login page
app.get("/login", (req, res) => {
  res.render("login", { message: null, csrfToken: req.csrfToken() });
});

// POST /login
app.post("/login", loginLimiter, async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  db.query(
    "SELECT id, username, password_plain, password_hash FROM users WHERE username = ? LIMIT 1",
    [username],
    async (err, results) => {
      if (err) return res.status(500).send("DB error");
      if (!results || results.length === 0)
        return res.render("login", {
          message: "Invalid credentials",
          csrfToken: req.csrfToken(),
        });

      const row = results[0];

      try {
        // 1) Plain password migration
        if (row.password_plain && row.password_plain === password) {
          await secure.migratePasswordOnLogin(row, password);
          req.session.userId = row.id;
          req.session.username = row.username;
          req.session.isAdmin = row.username === "admin";
          return res.redirect("/");
        }

        // 2) bcrypt check
        if (
          row.password_hash &&
          (await bcrypt.compare(password, row.password_hash))
        ) {
          req.session.userId = row.id;
          req.session.username = row.username;
          req.session.isAdmin = row.username === "admin";
          return res.redirect("/");
        }

        return res.render("login", {
          message: "Invalid credentials",
          csrfToken: req.csrfToken(),
        });
      } catch (e) {
        console.error("Login error:", e);
        return res.status(500).send("Server error");
      }
    }
  );
});

// Logout
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error("Session destroy error:", err);
    res.redirect("/");
  });
});

// Create a post
app.get("/post", requireAuth, (req, res) => {
  res.render("post", { csrfToken: req.csrfToken() });
});

app.post("/post", requireAuth, (req, res) => {
  const title = req.body.title ? String(req.body.title).trim() : "";
  const body = req.body.body ? xss(String(req.body.body)) : "";
  const sql = "INSERT INTO posts (title, body) VALUES (?, ?)";

  db.query(sql, [title, body], (err, result) => {
    if (err) return res.status(500).send("DB error");
    secure.regenerateSession(req, res, () => {
      req.session.userId = req.session.userId;
      req.session.username = req.session.username;
      req.session.isAdmin = req.session.username === "admin";
      res.redirect("/");
    });
  });
});

// Search
app.get("/search", (req, res) => {
  let q = String(req.query.q || "")
    .slice(0, 200)
    .trim();
  const like = `%${q}%`;

  db.query(
    "SELECT id, title, body FROM posts WHERE title LIKE ? OR body LIKE ? LIMIT 100",
    [like, like],
    (err, rows) => {
      if (err) return res.status(500).send("DB error");
      res.render("search", { q, results: rows });
    }
  );
});

// Reset DB (protected)
app.get("/reset-db", requireAuth, protectResetDb, (req, res) => {
  const init = fs.readFileSync(
    path.join(__dirname, "scripts", "init_db.sql"),
    "utf8"
  );
  db.query(init, (err) => {
    if (err) return res.status(500).send("DB init error");
    res.send('DB reset done. <a href="/">Home</a>');
  });
});

// --- Start server ---
const PORT = process.env.PORT || 4000;
app.listen(PORT, "127.0.0.1", () => {
  console.log(`Secure app listening on http://127.0.0.1:${PORT}`);
});
