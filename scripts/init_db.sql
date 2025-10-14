CREATE DATABASE IF NOT EXISTS my_db;
USE my_db;

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS posts;

CREATE TABLE users (
   id INT AUTO_INCREMENT PRIMARY KEY,
   username VARCHAR(255) UNIQUE,
   password_plain TEXT,
   password_hash TEXT
);

CREATE TABLE posts (
   id INT AUTO_INCREMENT PRIMARY KEY,
   title TEXT,
   body TEXT
);

INSERT INTO users (username, password_plain, password_hash) VALUES ('admin', 'admin', '');
INSERT INTO users (username, password_plain, password_hash) VALUES ('nathan', 'coucou', '');
INSERT INTO posts (title, body) VALUES ('Welcome', 'Bienvenue sur le mini-blog de fou furieux.');
INSERT INTO posts (title, body) VALUES ('Règles', 'Aucune règle c''est pas mal non plus.');
