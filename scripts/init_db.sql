CREATE DATABASE IF NOT EXISTS my_db;
USE my_db;

SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS logs;
DROP TABLE IF EXISTS avatars;
DROP TABLE IF EXISTS posts;
DROP TABLE IF EXISTS users;

SET FOREIGN_KEY_CHECKS = 1;

CREATE TABLE users (
   id INT AUTO_INCREMENT PRIMARY KEY,
   username VARCHAR(255) UNIQUE,
   password_plain TEXT,
   password_hash TEXT,
   bio TEXT
);

CREATE TABLE posts (
   id INT AUTO_INCREMENT PRIMARY KEY,
   title TEXT,
   body TEXT
);

CREATE TABLE logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NULL,
  username VARCHAR(255) NULL,
  action VARCHAR(255) NOT NULL,
  details TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE avatars (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  filename VARCHAR(255) NOT NULL,
  is_active BOOLEAN DEFAULT FALSE,
  uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

INSERT INTO users (username, password_plain, password_hash) VALUES ('admin', 'admin', '');
INSERT INTO users (username, password_plain, password_hash) VALUES ('nathan', 'coucou', '');

INSERT INTO posts (title, body) VALUES ('Welcome', 'Bienvenue sur le mini-blog de fou furieux.');
INSERT INTO posts (title, body) VALUES ('Règles', 'Aucune règle c''est pas mal non plus.');
