"""Authentication blueprint for a small Flask + SQLite application.

Passwords are stored only as Werkzeug password hashes, never as plaintext.
"""
import re
import sqlite3

from flask import Blueprint, current_app, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

auth_bp = Blueprint("auth", __name__)

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{3,32}$")
MIN_PASSWORD_LENGTH = 12


def get_db():
    """Open a SQLite connection using the path configured by the Flask app."""
    connection = sqlite3.connect(current_app.config["DATABASE"])
    connection.row_factory = sqlite3.Row
    return connection


def init_auth_db():
    """Create the users table if it does not already exist."""
    with get_db() as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


def validate_credentials(username, password):
    """Return an error message, or None when the supplied values are valid."""
    if not isinstance(username, str) or not _USERNAME_RE.fullmatch(username):
        return "Логін має містити 3–32 символи: латинські літери, цифри, _ або -."
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        return f"Пароль має містити щонайменше {MIN_PASSWORD_LENGTH} символів."
    if len(password) > 1024:
        return "Пароль занадто довгий."
    return None


def register_user(username, password):
    """Create a user. Return (user_id, None) or (None, error_message)."""
    error = validate_credentials(username, password)
    if error:
        return None, error

    password_hash = generate_password_hash(password)
    try:
        with get_db() as db:
            cursor = db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        return None, "Користувач із таким логіном уже існує."

    return user_id, None


def authenticate_user(username, password):
    """Return the user row if credentials match, otherwise None."""
    if not isinstance(username, str) or not isinstance(password, str):
        return None

    with get_db() as db:
        user = db.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if user is None or not check_password_hash(user["password_hash"], password):
        return None
    return user


@auth_bp.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    user_id, error = register_user(data.get("username"), data.get("password"))
    if error:
        return jsonify(error=error), 400
    return jsonify(message="Реєстрацію успішно завершено.", user_id=user_id), 201


@auth_bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="Потрібно вказати логін і пароль."), 400

    user = authenticate_user(username, password)
    if user is None:
        return jsonify(error="Неправильний логін або пароль."), 401

    # Clear any pre-existing session data before establishing the new session.
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return jsonify(message="Вхід виконано.", username=user["username"]), 200


@auth_bp.post("/logout")
def logout():
    session.clear()
    return jsonify(message="Вихід виконано."), 200
