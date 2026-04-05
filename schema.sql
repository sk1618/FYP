-- schema.sql
-- Run this once to set up the database for the FYP Security Monitoring Dashboard.
-- Usage: mysql -u your_user -p your_database < schema.sql

CREATE TABLE IF NOT EXISTS alerts (
  id              INT           NOT NULL AUTO_INCREMENT,
  source_ip       VARCHAR(45)   NOT NULL,
  destination_ip  VARCHAR(45)   NOT NULL,
  activity_type   VARCHAR(100)  NOT NULL,
  severity        ENUM('Low','Medium','High') NOT NULL DEFAULT 'Low',
  description     TEXT,
  timestamp       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id          INT           NOT NULL AUTO_INCREMENT,
  target_ip   VARCHAR(45)   NOT NULL,
  vuln_name   VARCHAR(150)  NOT NULL,
  severity    ENUM('Low','Medium','High') NOT NULL DEFAULT 'High',
  description TEXT,
  scan_date   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
