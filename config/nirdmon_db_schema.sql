-- Version: 2
-- Nirdmon MySQL Schema
-- Load into MySQL with:
-- mysql -u nirdmon_user -p nirdmon_db < config/nirdmon_db_schema.sql

CREATE DATABASE IF NOT EXISTS nirdmon_db;
USE nirdmon_db;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS monitored_domains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    uptime_status ENUM('OK', 'WARN', 'ERROR', 'UNKNOWN') DEFAULT 'UNKNOWN',
    ssl_status ENUM('OK', 'WARN', 'ERROR', 'UNKNOWN') DEFAULT 'UNKNOWN',
    dns_status ENUM('OK', 'WARN', 'ERROR', 'UNKNOWN') DEFAULT 'UNKNOWN',
    smtp_status ENUM('OK', 'WARN', 'ERROR', 'UNKNOWN') DEFAULT 'UNKNOWN',
    last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

