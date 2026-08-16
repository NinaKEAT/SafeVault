-- SafeVault Database Schema (SQLite)
-- These tables are created automatically by EF Core migrations.
-- This file documents the schema for reference.

CREATE TABLE IF NOT EXISTS Users (
    UserID    INTEGER PRIMARY KEY AUTOINCREMENT,
    Username  TEXT NOT NULL UNIQUE,
    PasswordHash TEXT NOT NULL,
    Email     TEXT NOT NULL UNIQUE,
    Role      TEXT NOT NULL DEFAULT 'user',
    CreatedAt TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS FinancialRecords (
    RecordID    INTEGER PRIMARY KEY AUTOINCREMENT,
    UserID      INTEGER NOT NULL,
    Amount      REAL NOT NULL,
    Description TEXT NOT NULL DEFAULT '',
    CreatedAt   TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (UserID) REFERENCES Users(UserID) ON DELETE CASCADE
);
