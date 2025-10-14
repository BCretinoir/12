// app.secure.js
const path = require("path");
const helmet = require("helmet");
const session = require("express-session");
const csrf = require("csurf");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcrypt");
const xss = require("xss");
const MySQLStore = require("express-mysql-session")(session);

const DEFAULTS = {
  sessionSecret: process.env.SESSION_SECRET || "please-change-me",
  sessionCookieName: "sid",
  sessionMaxAgeMs: 24 * 60 * 60 * 1000,
  saltRounds: 12,
  loginRateLimit: { windowMs: 15 * 60 * 1000, max: 8 },
  globalRateLimit: { windowMs: 60 * 1000, max: 200 },
  csp: "default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self';",
  adminResetTokenEnv: "ADMIN_RESET_TOKEN",
};

function sid(req, res, next) {
  if (!req.session) return next();
  req.session.sid = req.sessionID;
  req.session.sidMatched = true;
  next();
}

function initSecurity(app, db, opts = {}) {
  const cfg = Object.assign({}, DEFAULTS, opts);

  // --- Security headers & Helmet ---
  app.use(helmet());
  app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", cfg.csp);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer-when-downgrade");
    next();
  });

  // --- Session store ---
  app.use(
    session({
      store: new MySQLStore({
        host: "localhost",
        user: "root",
        password: "",
        database: "my_db",
      }),
      name: cfg.sessionCookieName,
      secret: cfg.sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: { httpOnly: true, sameSite: "lax", maxAge: cfg.sessionMaxAgeMs },
    })
  );

  app.use(sid);

  // --- CSRF protection ---
  app.use(csrf());
  app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    next();
  });

  // --- Rate limiting ---
  const globalLimiter = rateLimit({
    windowMs: cfg.globalRateLimit.windowMs,
    max: cfg.globalRateLimit.max,
    standardHeaders: true,
    legacyHeaders: false,
  });
  app.use(globalLimiter);

  const loginLimiter = rateLimit({
    windowMs: cfg.loginRateLimit.windowMs,
    max: cfg.loginRateLimit.max,
    message: "Too many login attempts from this IP, try later.",
    standardHeaders: true,
    legacyHeaders: false,
  });

  // --- Helpers ---
  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function sanitizeHtml(input) {
    return xss(String(input || ""), {
      whiteList: {},
      stripTagBody: ["script"],
    });
  }

  async function migratePasswordOnLogin(row, providedPassword) {
    if (!row) return { migrated: false };
    if (row.password_plain && row.password_plain === providedPassword) {
      const hash = await bcrypt.hash(providedPassword, cfg.saltRounds);
      return new Promise((resolve, reject) => {
        db.query(
          "UPDATE users SET password_hash = ?, password_plain = NULL WHERE id = ?",
          [hash, row.id],
          (err) => (err ? reject(err) : resolve({ migrated: true }))
        );
      });
    }
    return { migrated: false };
  }

  function regenerateSession(req, res, next) {
    const { userId, username, isAdmin } = req.session;
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = userId;
      req.session.username = username;
      req.session.isAdmin = isAdmin;
      next();
    });
  }

  function requireAuth(req, res, next) {
    if (req.session && req.session.userId) return next();
    return res.redirect(
      `/login?next=${encodeURIComponent(req.originalUrl || "/")}`
    );
  }

  function protectResetDb(req, res, next) {
    const token = process.env[cfg.adminResetTokenEnv];
    const provided = req.query.token || req.headers["x-admin-token"];
    if ((token && provided === token) || (req.session && req.session.isAdmin))
      return next();
    return res.status(403).send("Forbidden");
  }

  async function logAction(db, req, action, details = null) {
    const userId = req.session?.userId || null;
    const username = req.session?.username || null;
    const sql =
      "INSERT INTO logs (user_id, username, action, details) VALUES (?, ?, ?, ?)";
    return new Promise((resolve, reject) => {
      db.query(sql, [userId, username, action, details], (err, result) => {
        if (err) return reject(err);
        resolve(result.insertId);
      });
    });
  }

  function safeRenderMiddleware(req, res, next) {
    next();
  }

  return {
    escapeHtml,
    sanitizeHtml,
    migratePasswordOnLogin,
    loginLimiter,
    requireAuth,
    protectResetDb,
    safeRenderMiddleware,
    regenerateSession,
    sid,
    logAction,
  };
}

module.exports = { initSecurity };
