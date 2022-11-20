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

-- password 'testPwd' hashed with sha512
INSERT INTO tblUser (userID, username, pwd, token) VALUES
(1, 'testUser', 'd803b4b4121d445b220d94dabc43d5f9f625a28e15089ec0edd4c3731ce3abf3bea92f542a99455625833e379d3d6165d44a9a898e9adb8f5f1cdb3381a44ff2', 123456);
                 
CREATE TABLE tblRoleUser (
  userID int(11) NOT NULL,
  roleID int(11) NOT NULL
);

INSERT INTO tblRoleUser (userID, roleID) VALUES (1, 1);  -- Administrator
INSERT INTO tblRoleUser (userID, roleID) VALUES (1, 2);  -- Viewer

