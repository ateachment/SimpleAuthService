-- phpMyAdmin SQL init testdb
-- CAUTION: all existing data will be lost

CREATE USER IF NOT EXISTS 'testUser'@'localhost' IDENTIFIED BY 'testPwd';
GRANT ALL PRIVILEGES ON *.* TO 'testUser'@'localhost';

DROP DATABASE IF EXISTS testDb;
CREATE DATABASE testDb; 

USE testDb;

CREATE TABLE tblRole (
  roleID tinyint(4) NOT NULL AUTO_INCREMENT,
  rolename varchar(20) NOT NULL,
  PRIMARY KEY(roleID)
);

INSERT INTO tblRole (roleID, rolename) VALUES
(1, 'Administrator'),
(2, 'Viewer');

CREATE TABLE tblUser (
  userID int(11) NOT NULL AUTO_INCREMENT,
  username varchar(50) DEFAULT NULL,
  pwd varchar(128) DEFAULT NULL,
  totpActivated boolean,
  totpKey varchar(32),
  PRIMARY KEY(userID)
);

-- password 'testPwd' hashed with argon2
INSERT INTO tblUser (userID, username, pwd, totpActivated) VALUES
(1, 'testUser', '$argon2id$v=19$m=65536,t=3,p=4$AO8XsjZEt2aaGL7Xh/4DeQ$vTplDqP6zL3Kk8uCUu9rPV1+dT3hSmo8Si8DDH3nhQU', false);
                 
CREATE TABLE tblRoleUser (
  userID int(11) NOT NULL,
  roleID int(11) NOT NULL
);

INSERT INTO tblRoleUser (userID, roleID) VALUES (1, 1);  -- Administrator
INSERT INTO tblRoleUser (userID, roleID) VALUES (1, 2);  -- Viewer

-- Passkey Authentication - more than one passkey per user for different devices needed.
CREATE TABLE tblpasskey (
  credentialID VARBINARY(255) NOT NULL,  -- short binary identifier for the passkey credential, unique for each passkey
  userID INT NOT NULL,
  publicKey BLOB NOT NULL,  -- larger binary data structure (COSE key)
  signCount INT DEFAULT 0,  -- to prevent replay attacks by tracking the number of times a passkey has been used
  created DATETIME DEFAULT current_timestamp(),
  PRIMARY KEY (credentialID)
);

