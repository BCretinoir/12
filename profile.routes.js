// profile.routes.js
const express = require("express");
const path = require("path");
const fs = require("fs");
const multer = require("multer");

module.exports = function (db, secure) {
  const router = express.Router();
  const uploadDir = path.join(__dirname, "data", "uploads");

  // Multer configuration
  const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname);
      const name = `${Date.now()}_${Math.random()
        .toString(36)
        .substring(2, 8)}${ext}`;
      cb(null, name);
    },
  });
  const upload = multer({ storage });

  // CSRF protection
  

  // --- ROUTES ---

  // Affichage du profil
  router.get("/",  (req, res) => {
    
    db.query(
      "SELECT * FROM avatars WHERE user_id = ? ORDER BY id DESC",
      [req.session.userId],
      (err, avatars) => {
        if (err) return res.status(500).send("DB error");

        db.query(
          "SELECT bio FROM users WHERE id = ?",
          [req.session.userId],
          (err2, results) => {
            if (err2) return res.status(500).send("DB error");

            const user = {
              username: req.session.username,
              bio: results[0]?.bio || "",
            };

            res.render("profile", {
              user,
              avatars,
            });
          }
        );
      }
    );
  });

  router.post("/edit",  (req, res) => {
    const bio = req.body.bio || "";
    db.query(
      "UPDATE users SET bio = ? WHERE id = ?",
      [bio, req.session.userId],
      async (err) => {
        if (err) return res.status(500).send("DB error");
        await secure
          .logAction(db, req, "profile_edit", "Bio updated")
          .catch(console.error);
        res.redirect("/profile");
      }
    );
  });

  router.post(
    "/avatar",
    upload.single("avatar"),
    async (req, res) => {
      if (!req.file) return res.status(400).send("No file uploaded");
      const filename = req.file.filename;

      db.query(
        "INSERT INTO avatars (user_id, filename, is_active) VALUES (?, ?, 0)",
        [req.session.userId, filename],
        async (err) => {
          if (err) return res.status(500).send("DB error");
          await secure
            .logAction(db, req, "avatar_upload", filename)
            .catch(console.error);
          res.redirect("/profile");
        }
      );
    }
  );

  router.post("/avatar/activate",(req, res) => {
    const avatarId = req.body.avatarId;

    db.query(
      "UPDATE avatars SET is_active = 0 WHERE user_id = ?",
      [req.session.userId],
      (err) => {
        if (err) return res.status(500).send("DB error");

        db.query(
          "UPDATE avatars SET is_active = 1 WHERE id = ? AND user_id = ?",
          [avatarId, req.session.userId],
          async (err2) => {
            if (err2) return res.status(500).send("DB error");
            await secure
              .logAction(
                db,
                req,
                "avatar_activate",
                `Avatar ${avatarId} activated`
              )
              .catch(console.error);
            res.redirect("/profile");
          }
        );
      }
    );
  });

  // Suppression d'un avatar
  router.post("/avatar/delete", (req, res) => {
    const avatarId = req.body.avatarId;

    db.query(
      "SELECT filename, is_active FROM avatars WHERE id = ? AND user_id = ?",
      [avatarId, req.session.userId],
      (err, results) => {
        if (err || !results[0]) return res.status(500).send("DB error");
        if (results[0].is_active)
          return res.status(400).send("Cannot delete active avatar");

        const filepath = path.join(uploadDir, results[0].filename);
        fs.unlink(filepath, () => {
          db.query(
            "DELETE FROM avatars WHERE id = ? AND user_id = ?",
            [avatarId, req.session.userId],
            async (err2) => {
              if (err2) return res.status(500).send("DB error");
              await secure
                .logAction(db, req, "avatar_delete", results[0].filename)
                .catch(console.error);
              res.redirect("/profile");
            }
          );
        });
      }
    );
  });

  // Récupération d'un fichier avatar
  router.get("/avatar/:filename", (req, res) => {
    const filePath = path.join(uploadDir, req.params.filename);
    if (!fs.existsSync(filePath)) return res.status(404).send("Not found");
    res.sendFile(filePath);
  });

  return router;
};
