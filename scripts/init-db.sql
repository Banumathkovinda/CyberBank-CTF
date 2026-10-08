-- ============================================
-- CyberBank: Operation BlackVault
-- Database Initialization Script
-- ============================================
-- This script runs automatically on first container start
-- via /docker-entrypoint-initdb.d/
--
-- NOTE: MYSQL_DATABASE, MYSQL_USER, and MYSQL_PASSWORD env vars
-- already create the database and user. This script sets up
-- additional privileges and verifies the configuration.
-- ============================================

-- Ensure the cyberbank database exists (created by env var, this is a safety net)
CREATE DATABASE IF NOT EXISTS `cyberbank`
 CHARACTER SET utf8mb4
 COLLATE utf8mb4_unicode_ci;

-- Grant the application user full privileges on the cyberbank database ONLY
-- The app user should NEVER have global or root-level privileges
GRANT ALL PRIVILEGES ON `cyberbank`.* TO 'cyberbank_user'@'%';
FLUSH PRIVILEGES;

-- Switch to the cyberbank database
USE `cyberbank`;

-- ============================================
-- Schema placeholder tables (will be expanded in Phase 3)
-- These exist to verify the database is working correctly
-- ============================================

-- Platform metadata table
CREATE TABLE IF NOT EXISTS `platform_info` (
 `id` INT AUTO_INCREMENT PRIMARY KEY,
 `key_name` VARCHAR(100) NOT NULL UNIQUE,
 `value` TEXT NOT NULL,
 `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert platform metadata
INSERT INTO `platform_info` (`key_name`, `value`) VALUES
 ('platform_name', 'CyberBank: Operation BlackVault'),
 ('version', '0.1.0'),
 ('phase', '2'),
 ('initialized_at', NOW())
ON DUPLICATE KEY UPDATE `value` = VALUES(`value`), `updated_at` = NOW();

-- Verification: Show what was created
SELECT '[OK] CyberBank database initialized successfully' AS status;
SELECT * FROM `platform_info`;
