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
  token bigint(64) NOT NULL,
  tokenExpiry timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY(userID)
);

-- password 'testPwd' hashed with argon2
INSERT INTO tblUser (userID, username, pwd, token) VALUES
(1, 'testUser', '$argon2id$v=19$m=65536,t=3,p=4$AO8XsjZEt2aaGL7Xh/4DeQ$vTplDqP6zL3Kk8uCUu9rPV1+dT3hSmo8Si8DDH3nhQU', 123456);
                 
CREATE TABLE tblRoleUser (
  userID int(11) NOT NULL,
  roleID int(11) NOT NULL
);

INSERT INTO tblRoleUser (userID, roleID) VALUES (1, 1);  -- Administrator
INSERT INTO tblRoleUser (userID, roleID) VALUES (1, 2);  -- Viewer

