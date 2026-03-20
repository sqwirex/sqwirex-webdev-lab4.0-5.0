from __future__ import annotations

import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "instance" / "app.db"

FULL_NAME = "Николаев Алексей Владимирович"
GROUP = "241-3211"
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    REMEMBER_COOKIE_DURATION=86400 * 30,
)
application = app

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = "Для доступа к запрашиваемой странице необходимо пройти процедуру аутентификации."
login_manager.login_message_category = "warning"
login_manager.init_app(app)


class DbUser(UserMixin):
    def __init__(self, row: sqlite3.Row):
        self.id = str(row["id"])
        self.login = row["login"]
        self.password_hash = row["password_hash"]
        self.last_name = row["last_name"]
        self.first_name = row["first_name"]
        self.middle_name = row["middle_name"]
        self.role_id = row["role_id"]
        self.created_at = row["created_at"]

    @property
    def full_name(self) -> str:
        parts = [self.last_name or "", self.first_name or "", self.middle_name or ""]
        return " ".join(part for part in parts if part).strip() or self.login


@login_manager.user_loader
def load_user(user_id: str) -> DbUser | None:
    row = query_one(
        "SELECT id, login, password_hash, last_name, first_name, middle_name, role_id, created_at FROM users WHERE id = ?",
        (user_id,),
    )
    return DbUser(row) if row else None


@app.context_processor
def inject_common_data() -> dict[str, Any]:
    return {
        "full_name": FULL_NAME,
        "group_number": GROUP,
        "current_year": datetime.now().year,
    }


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exception: Exception | None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def execute(query: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
    cur = get_db().execute(query, params)
    get_db().commit()
    return cur


def query_all(query: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    return get_db().execute(query, params).fetchall()


def query_one(query: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
    return get_db().execute(query, params).fetchone()


def init_db() -> None:
    schema = """
    CREATE TABLE IF NOT EXISTS roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        description TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        login TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        last_name TEXT,
        first_name TEXT NOT NULL,
        middle_name TEXT,
        role_id INTEGER,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE SET NULL
    );
    """
    get_db().executescript(schema)
    seed_roles()
    seed_admin()
    get_db().commit()


def seed_roles() -> None:
    roles = [
        ("Администратор", "Полный доступ к управлению учётными записями."),
        ("Менеджер", "Пользователь с расширенными правами."),
        ("Пользователь", "Базовая роль пользователя системы."),
    ]
    for name, description in roles:
        execute(
            "INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)",
            (name, description),
        )


def seed_admin() -> None:
    row = query_one("SELECT id FROM users WHERE login = ?", ("user",))
    if row is None:
        admin_role = query_one("SELECT id FROM roles WHERE name = ?", ("Администратор",))
        execute(
            """
            INSERT INTO users (login, password_hash, last_name, first_name, middle_name, role_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "user",
                generate_password_hash("qwerty"),
                "Николаев",
                "Алексей",
                "Владимирович",
                admin_role["id"] if admin_role else None,
            ),
        )


LOGIN_RE = re.compile(r"^[A-Za-z0-9]{5,}$")
PASSWORD_ALLOWED_RE = re.compile(r"^[A-Za-zА-Яа-яЁё0-9~!?@#$%^&*_\-+()\[\]{}><\\/|\"'.,:;]+$")
PASSWORD_HAS_UPPER_RE = re.compile(r"[A-ZА-ЯЁ]")
PASSWORD_HAS_LOWER_RE = re.compile(r"[a-zа-яё]")
PASSWORD_HAS_DIGIT_RE = re.compile(r"[0-9]")


def validate_login(login: str, *, current_user_id: int | None = None) -> str | None:
    if not login.strip():
        return "Поле не может быть пустым."
    if len(login.strip()) < 5:
        return "Логин должен содержать не менее 5 символов."
    if not LOGIN_RE.fullmatch(login.strip()):
        return "Логин должен состоять только из латинских букв и цифр."
    existing = query_one("SELECT id FROM users WHERE login = ?", (login.strip(),))
    if existing and existing["id"] != current_user_id:
        return "Пользователь с таким логином уже существует."
    return None


def validate_required(value: str, label: str) -> str | None:
    if not value.strip():
        return f"Поле «{label}» не может быть пустым."
    return None


def validate_password(password: str) -> list[str]:
    errors: list[str] = []
    if not password:
        errors.append("Поле не может быть пустым.")
        return errors
    if len(password) < 8:
        errors.append("Пароль должен содержать не менее 8 символов.")
    if len(password) > 128:
        errors.append("Пароль должен содержать не более 128 символов.")
    if any(ch.isspace() for ch in password):
        errors.append("Пароль не должен содержать пробелы.")
    if not PASSWORD_ALLOWED_RE.fullmatch(password):
        errors.append("Пароль содержит недопустимые символы.")
    if not PASSWORD_HAS_UPPER_RE.search(password):
        errors.append("Пароль должен содержать хотя бы одну заглавную букву.")
    if not PASSWORD_HAS_LOWER_RE.search(password):
        errors.append("Пароль должен содержать хотя бы одну строчную букву.")
    if not PASSWORD_HAS_DIGIT_RE.search(password):
        errors.append("Пароль должен содержать хотя бы одну цифру.")
    return errors


def role_choices() -> list[sqlite3.Row]:
    return query_all("SELECT id, name, description FROM roles ORDER BY name")


def get_user_with_role(user_id: int) -> sqlite3.Row | None:
    return query_one(
        """
        SELECT users.id, users.login, users.password_hash, users.last_name, users.first_name, users.middle_name,
               users.role_id, users.created_at, roles.name AS role_name, roles.description AS role_description
        FROM users
        LEFT JOIN roles ON roles.id = users.role_id
        WHERE users.id = ?
        """,
        (user_id,),
    )


def full_name_from_row(row: sqlite3.Row) -> str:
    parts = [row["last_name"] or "", row["first_name"] or "", row["middle_name"] or ""]
    return " ".join(part for part in parts if part).strip() or row["login"]


@app.route("/")
def index():
    users = query_all(
        """
        SELECT users.id, users.login, users.last_name, users.first_name, users.middle_name,
               roles.name AS role_name
        FROM users
        LEFT JOIN roles ON roles.id = users.role_id
        ORDER BY users.id
        """
    )
    return render_template("index.html", title="Список пользователей", users=users, full_name_from_row=full_name_from_row)


@app.route("/counter")
def counter():
    visits = session.get("counter_visits", 0) + 1
    session["counter_visits"] = visits
    return render_template("counter.html", title="Счётчик посещений", visits=visits)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        login_value = request.form.get("login", "").strip()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"

        row = query_one(
            "SELECT id, login, password_hash, last_name, first_name, middle_name, role_id, created_at FROM users WHERE login = ?",
            (login_value,),
        )

        if row and check_password_hash(row["password_hash"], password):
            login_user(DbUser(row), remember=remember)
            flash("Вы успешно вошли в систему.", "success")
            next_page = request.args.get("next")
            if next_page and next_page.startswith("/"):
                return redirect(next_page)
            return redirect(url_for("index"))

        flash("Неверно введён логин или пароль.", "danger")
        return render_template("login.html", title="Вход", form=request.form)

    return render_template("login.html", title="Вход", form={})


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Вы вышли из системы.", "info")
    return redirect(url_for("index"))


@app.route("/users/<int:user_id>")
def user_view(user_id: int):
    user = get_user_with_role(user_id)
    if user is None:
        flash("Пользователь не найден.", "warning")
        return redirect(url_for("index"))
    return render_template("user_view.html", title="Просмотр пользователя", user=user)


@app.route("/users/create", methods=["GET", "POST"])
@login_required
def user_create():
    roles = role_choices()
    form_data = {
        "login": "",
        "last_name": "",
        "first_name": "",
        "middle_name": "",
        "role_id": "",
    }
    errors: dict[str, str] = {}

    if request.method == "POST":
        form_data = {
            "login": request.form.get("login", "").strip(),
            "last_name": request.form.get("last_name", "").strip(),
            "first_name": request.form.get("first_name", "").strip(),
            "middle_name": request.form.get("middle_name", "").strip(),
            "role_id": request.form.get("role_id", "").strip(),
        }
        password = request.form.get("password", "")

        login_error = validate_login(form_data["login"])
        if login_error:
            errors["login"] = login_error

        for field_name, label in (("last_name", "Фамилия"), ("first_name", "Имя")):
            error = validate_required(form_data[field_name], label)
            if error:
                errors[field_name] = error

        password_errors = validate_password(password)
        if password_errors:
            errors["password"] = " ".join(password_errors)

        role_id: int | None = None
        if form_data["role_id"]:
            try:
                role_id = int(form_data["role_id"])
            except ValueError:
                errors["role_id"] = "Выберите корректную роль."

        if not errors:
            try:
                execute(
                    """
                    INSERT INTO users (login, password_hash, last_name, first_name, middle_name, role_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        form_data["login"],
                        generate_password_hash(password),
                        form_data["last_name"],
                        form_data["first_name"],
                        form_data["middle_name"] or None,
                        role_id,
                    ),
                )
                flash("Пользователь успешно создан.", "success")
                return redirect(url_for("index"))
            except sqlite3.IntegrityError:
                flash("Не удалось сохранить пользователя. Проверьте корректность данных.", "danger")
            except Exception:
                flash("При сохранении пользователя произошла ошибка.", "danger")

        flash("Исправьте ошибки в форме.", "danger")

    return render_template(
        "user_form_page.html",
        title="Создание пользователя",
        page_title="Создание пользователя",
        submit_label="Сохранить",
        roles=roles,
        form_data=form_data,
        errors=errors,
        is_edit=False,
    )


@app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
def user_edit(user_id: int):
    user = get_user_with_role(user_id)
    if user is None:
        flash("Пользователь не найден.", "warning")
        return redirect(url_for("index"))

    roles = role_choices()
    form_data = {
        "last_name": user["last_name"] or "",
        "first_name": user["first_name"] or "",
        "middle_name": user["middle_name"] or "",
        "role_id": str(user["role_id"] or ""),
    }
    errors: dict[str, str] = {}

    if request.method == "POST":
        form_data = {
            "last_name": request.form.get("last_name", "").strip(),
            "first_name": request.form.get("first_name", "").strip(),
            "middle_name": request.form.get("middle_name", "").strip(),
            "role_id": request.form.get("role_id", "").strip(),
        }

        for field_name, label in (("last_name", "Фамилия"), ("first_name", "Имя")):
            error = validate_required(form_data[field_name], label)
            if error:
                errors[field_name] = error

        role_id: int | None = None
        if form_data["role_id"]:
            try:
                role_id = int(form_data["role_id"])
            except ValueError:
                errors["role_id"] = "Выберите корректную роль."

        if not errors:
            try:
                execute(
                    """
                    UPDATE users
                    SET last_name = ?, first_name = ?, middle_name = ?, role_id = ?
                    WHERE id = ?
                    """,
                    (
                        form_data["last_name"],
                        form_data["first_name"],
                        form_data["middle_name"] or None,
                        role_id,
                        user_id,
                    ),
                )
                flash("Данные пользователя успешно обновлены.", "success")
                return redirect(url_for("index"))
            except Exception:
                flash("При обновлении пользователя произошла ошибка.", "danger")

        flash("Исправьте ошибки в форме.", "danger")

    return render_template(
        "user_form_page.html",
        title="Редактирование пользователя",
        page_title="Редактирование пользователя",
        submit_label="Сохранить",
        roles=roles,
        form_data=form_data,
        errors=errors,
        is_edit=True,
        user=user,
    )


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
def user_delete(user_id: int):
    user = get_user_with_role(user_id)
    if user is None:
        flash("Пользователь не найден.", "warning")
        return redirect(url_for("index"))

    try:
        execute("DELETE FROM users WHERE id = ?", (user_id,))
        flash("Пользователь успешно удалён.", "success")
    except Exception:
        flash("При удалении пользователя произошла ошибка.", "danger")
    return redirect(url_for("index"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    errors: dict[str, str] = {}
    if request.method == "POST":
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        new_password_repeat = request.form.get("new_password_repeat", "")

        user_row = query_one("SELECT * FROM users WHERE id = ?", (current_user.id,))
        if user_row is None or not check_password_hash(user_row["password_hash"], old_password):
            errors["old_password"] = "Старый пароль введён неверно."

        password_errors = validate_password(new_password)
        if password_errors:
            errors["new_password"] = " ".join(password_errors)

        if new_password != new_password_repeat:
            errors["new_password_repeat"] = "Новые пароли не совпадают."

        if not errors:
            try:
                execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (generate_password_hash(new_password), current_user.id),
                )
                flash("Пароль успешно изменён.", "success")
                return redirect(url_for("index"))
            except Exception:
                flash("Не удалось изменить пароль.", "danger")
        else:
            flash("Исправьте ошибки в форме смены пароля.", "danger")

        return render_template("change_password.html", title="Изменить пароль", errors=errors)

    return render_template("change_password.html", title="Изменить пароль", errors={})


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(debug=True)
