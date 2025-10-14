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
  sessionMaxAgeMs: 24 * 60 * 60 * 1000, // 1 day
  saltRounds: 12,
  loginRateLimit: { windowMs: 15 * 60 * 1000, max: 8 }, // 8 attempts / 15min
  globalRateLimit: { windowMs: 60 * 1000, max: 200 }, // 200 req / min default
  csp: "default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self';",
  sessionsDbFile: "sessions.sqlite",
  sessionsDir: path.join(__dirname, "data"),
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

  // 1) Helmet + CSP + HSTS
  app.use(helmet());
  app.use(helmet({ crossOriginEmbedderPolicy: true }));
  app.use(helmet({ crossOriginEmbedderPolicy: { policy: "credentialless" } }));
  app.use(helmet({ crossOriginOpenerPolicy: { policy: "same-origin" } }));
  app.use(helmet.strictTransportSecurity());
  app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", cfg.csp);
    if (process.env.NODE_ENV === "production") {
      res.setHeader(
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains; preload"
      );
    }
    next();
  });

  // 2) Session store (SQLite by default)
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
      cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: cfg.sessionMaxAgeMs,
      },
    })
  );

  app.use(sid);

  // 3) CSRF protection (after session middleware)
  app.use(csrf());
  app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    next();
  });

  // 4) Rate limiting
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
    message: "Too many login attempts from this IP, please try again later.",
    standardHeaders: true,
    legacyHeaders: false,
  });

  function requireAuth(req, res, next) {
    if (req.session && req.session.userId) return next();
    return res.redirect(
      `/login?next=${encodeURIComponent(req.originalUrl || "/")}`
    );
  }

  // Helpers

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
      whiteList: {}, // no tags by default
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
          function (err) {
            if (err) return reject(err);
            resolve({ migrated: true });
          }
        );
      });
    }
    return { migrated: false };
  }

  function requireAuth(req, res, next) {
    if (req.session && req.session.userId) return next();
    if (
      req.xhr ||
      (req.headers.accept && req.headers.accept.indexOf("json") > -1)
    ) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    return res.redirect(
      `/login?next=${encodeURIComponent(req.originalUrl || "/")}`
    );
  }

  function regenerateSession(req, res, next) {
    req.session.regenerate((err) => {
      if (err) return next(err);
      return next();
    });
  }

  function protectResetDb(req, res, next) {
    const token = process.env[cfg.adminResetTokenEnv];
    const provided = req.query.token || req.headers["x-admin-token"];
    if (token && provided && provided === token) return next();
    if (req.session && req.session.isAdmin) return next();
    return res.status(403).send("Forbidden");
  }

  function safeRenderMiddleware(req, res, next) {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer-when-downgrade");
    next();
  }

  const helpers = {
    escapeHtml,
    sanitizeHtml,
    migratePasswordOnLogin,
    loginLimiter,
    requireAuth,
    protectResetDb,
    safeRenderMiddleware,
    regenerateSession,
    sid,
  };

  app.locals.secure = helpers;

  return helpers;
}

module.exports = { initSecurity };
