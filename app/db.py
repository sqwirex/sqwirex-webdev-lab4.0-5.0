
import os
import sqlite3
from flask import g, current_app
from werkzeug.security import generate_password_hash

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(current_app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(current_app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    cur = db.cursor()

    cur.executescript("""
    CREATE TABLE IF NOT EXISTS roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        description TEXT
    );

    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        login TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        last_name TEXT,
        first_name TEXT NOT NULL,
        middle_name TEXT,
        role_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS visit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        path VARCHAR(100) NOT NULL,
        user_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    """)

    cur.execute("INSERT OR IGNORE INTO roles(id, name, description) VALUES (1, 'Администратор', 'Полный доступ')")
    cur.execute("INSERT OR IGNORE INTO roles(id, name, description) VALUES (2, 'Пользователь', 'Ограниченный доступ')")

    admin_hash = generate_password_hash('Admin123!')
    user_hash = generate_password_hash('User123!')

    cur.execute("""
        INSERT OR IGNORE INTO users(id, login, password_hash, last_name, first_name, middle_name, role_id)
        VALUES (1, 'admin', ?, 'Николаев', 'Алексей', 'Владимирович', 1)
    """, (admin_hash,))
    cur.execute("""
        INSERT OR IGNORE INTO users(id, login, password_hash, last_name, first_name, middle_name, role_id)
        VALUES (2, 'user', ?, 'Иванов', 'Иван', 'Иванович', 2)
    """, (user_hash,))

    db.commit()
    db.close()
