
import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from app.db import get_db, close_db, init_db
from app.utils import (
    validate_login, validate_name, validate_password, has_right, full_name
)
from app.reports import reports_bp

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'database.db')

app = Flask(__name__)
application = app
app.config['SECRET_KEY'] = 'super-secret-key-for-lab5'
app.config['DATABASE'] = DATABASE

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message = 'Для доступа к запрашиваемой странице необходимо пройти процедуру аутентификации.'
login_manager.login_message_category = 'warning'
login_manager.init_app(app)

app.teardown_appcontext(close_db)
app.register_blueprint(reports_bp)

class User(UserMixin):
    def __init__(self, row):
        self.id = row['id']
        self.login = row['login']
        self.password_hash = row['password_hash']
        self.last_name = row['last_name']
        self.first_name = row['first_name']
        self.middle_name = row['middle_name']
        self.role_id = row['role_id']
        self.role_name = row['role_name']

    @property
    def full_name(self):
        return full_name({
            'last_name': self.last_name,
            'first_name': self.first_name,
            'middle_name': self.middle_name,
            'login': self.login
        })

@login_manager.user_loader
def load_user(user_id):
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    row = db.execute(
        '''
        SELECT u.*, r.name AS role_name
        FROM users u
        LEFT JOIN roles r ON r.id = u.role_id
        WHERE u.id = ?
        ''',
        (user_id,)
    ).fetchone()
    db.close()
    if row:
        return User(row)
    return None

@app.before_request
def log_visit():
    if request.endpoint in ('static',):
        return
    if request.path.startswith('/static'):
        return
    db = get_db()
    user_id = current_user.id if current_user.is_authenticated else None
    db.execute(
        'INSERT INTO visit_logs(path, user_id) VALUES (?, ?)',
        (request.path[:100], user_id)
    )
    db.commit()

@app.context_processor
def inject_user_data():
    return {
        'full_name_footer': 'Николаев Алексей Владимирович',
        'group_number': '241-3211',
        'has_right': has_right,
    }

@app.route('/')
def index():
    db = get_db()
    rows = db.execute(
        '''
        SELECT u.id, u.login, u.last_name, u.first_name, u.middle_name, r.name AS role_name
        FROM users u
        LEFT JOIN roles r ON r.id = u.role_id
        ORDER BY u.id
        '''
    ).fetchall()
    return render_template('index.html', users=rows)

@app.route('/counter')
def counter():
    session['visits_count'] = session.get('visits_count', 0) + 1
    return render_template('counter.html', count=session['visits_count'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_value = request.form.get('login', '').strip()
        password = request.form.get('password', '')
        remember = bool(request.form.get('remember'))

        db = get_db()
        row = db.execute(
            '''
            SELECT u.*, r.name AS role_name
            FROM users u
            LEFT JOIN roles r ON r.id = u.role_id
            WHERE u.login = ?
            ''',
            (login_value,)
        ).fetchone()

        if row and check_password_hash(row['password_hash'], password):
            user = User(row)
            login_user(user, remember=remember)
            flash('Вы успешно вошли в систему.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))

        flash('Неверный логин или пароль.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))

@app.route('/users/<int:user_id>')
def user_view(user_id):
    db = get_db()
    row = db.execute(
        '''
        SELECT u.*, r.name AS role_name
        FROM users u
        LEFT JOIN roles r ON r.id = u.role_id
        WHERE u.id = ?
        ''',
        (user_id,)
    ).fetchone()
    if not row:
        flash('Пользователь не найден.', 'warning')
        return redirect(url_for('index'))

    if current_user.is_authenticated and has_right(current_user, 'view_profile', row):
        return render_template('user_view.html', user=row)

    if not current_user.is_authenticated:
        flash('У вас недостаточно прав для доступа к данной странице.', 'danger')
        return redirect(url_for('index'))

    flash('У вас недостаточно прав для доступа к данной странице.', 'danger')
    return redirect(url_for('index'))

@app.route('/users/create', methods=['GET', 'POST'])
@login_required
def user_create():
    if not has_right(current_user, 'create_user'):
        flash('У вас недостаточно прав для доступа к данной странице.', 'danger')
        return redirect(url_for('index'))

    db = get_db()
    roles = db.execute('SELECT * FROM roles ORDER BY id').fetchall()
    values = {'login': '', 'last_name': '', 'first_name': '', 'middle_name': '', 'role_id': ''}
    errors = {}

    if request.method == 'POST':
        values = {
            'login': request.form.get('login', '').strip(),
            'last_name': request.form.get('last_name', '').strip(),
            'first_name': request.form.get('first_name', '').strip(),
            'middle_name': request.form.get('middle_name', '').strip(),
            'role_id': request.form.get('role_id', '').strip(),
        }
        password = request.form.get('password', '')

        errors['login'] = validate_login(values['login'])
        errors['password'] = validate_password(password)
        errors['last_name'] = validate_name(values['last_name'])
        errors['first_name'] = validate_name(values['first_name'])
        errors = {k: v for k, v in errors.items() if v}

        if not errors:
            try:
                db.execute(
                    '''
                    INSERT INTO users(login, password_hash, last_name, first_name, middle_name, role_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ''',
                    (
                        values['login'],
                        generate_password_hash(password),
                        values['last_name'],
                        values['first_name'],
                        values['middle_name'] or None,
                        int(values['role_id']) if values['role_id'] else None,
                    )
                )
                db.commit()
                flash('Пользователь успешно создан.', 'success')
                return redirect(url_for('index'))
            except sqlite3.IntegrityError:
                errors['login'] = 'Пользователь с таким логином уже существует.'
                flash('При сохранении пользователя возникла ошибка.', 'danger')

    return render_template(
        'user_form_page.html',
        title='Создание пользователя',
        action_url=url_for('user_create'),
        values=values,
        errors=errors,
        roles=roles,
        submit_text='Сохранить',
        mode='create',
        current_user_obj=current_user
    )

@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def user_edit(user_id):
    db = get_db()
    user = db.execute(
        '''
        SELECT u.*, r.name AS role_name
        FROM users u
        LEFT JOIN roles r ON r.id = u.role_id
        WHERE u.id = ?
        ''',
        (user_id,)
    ).fetchone()
    if not user:
        flash('Пользователь не найден.', 'warning')
        return redirect(url_for('index'))

    if not has_right(current_user, 'edit_user', user):
        flash('У вас недостаточно прав для доступа к данной странице.', 'danger')
        return redirect(url_for('index'))

    roles = db.execute('SELECT * FROM roles ORDER BY id').fetchall()
    values = {
        'login': user['login'],
        'last_name': user['last_name'] or '',
        'first_name': user['first_name'] or '',
        'middle_name': user['middle_name'] or '',
        'role_id': str(user['role_id'] or ''),
    }
    errors = {}

    if request.method == 'POST':
        values.update({
            'last_name': request.form.get('last_name', '').strip(),
            'first_name': request.form.get('first_name', '').strip(),
            'middle_name': request.form.get('middle_name', '').strip(),
        })

        if current_user.role_name == 'Администратор':
            values['role_id'] = request.form.get('role_id', '').strip()
        else:
            values['role_id'] = str(user['role_id'] or '')

        errors['last_name'] = validate_name(values['last_name'])
        errors['first_name'] = validate_name(values['first_name'])
        errors = {k: v for k, v in errors.items() if v}

        if not errors:
            try:
                db.execute(
                    '''
                    UPDATE users
                    SET last_name = ?, first_name = ?, middle_name = ?, role_id = ?
                    WHERE id = ?
                    ''',
                    (
                        values['last_name'],
                        values['first_name'],
                        values['middle_name'] or None,
                        int(values['role_id']) if values['role_id'] else None,
                        user_id
                    )
                )
                db.commit()
                flash('Пользователь успешно обновлён.', 'success')
                return redirect(url_for('index'))
            except sqlite3.DatabaseError:
                flash('При обновлении пользователя возникла ошибка.', 'danger')

    return render_template(
        'user_form_page.html',
        title='Редактирование пользователя',
        action_url=url_for('user_edit', user_id=user_id),
        values=values,
        errors=errors,
        roles=roles,
        submit_text='Сохранить',
        mode='edit',
        current_user_obj=current_user
    )

@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def user_delete(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        flash('Пользователь не найден.', 'warning')
        return redirect(url_for('index'))

    if not has_right(current_user, 'delete_user'):
        flash('У вас недостаточно прав для доступа к данной странице.', 'danger')
        return redirect(url_for('index'))

    try:
        db.execute('DELETE FROM users WHERE id = ?', (user_id,))
        db.commit()
        flash('Пользователь успешно удалён.', 'success')
    except sqlite3.DatabaseError:
        flash('Не удалось удалить пользователя.', 'danger')
    return redirect(url_for('index'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    errors = {}
    if request.method == 'POST':
        old_password = request.form.get('old_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not check_password_hash(current_user.password_hash, old_password):
            errors['old_password'] = 'Старый пароль введён неверно.'

        password_error = validate_password(new_password)
        if password_error:
            errors['new_password'] = password_error

        if new_password != confirm_password:
            errors['confirm_password'] = 'Новые пароли не совпадают.'

        if errors:
            flash('Исправьте ошибки в форме.', 'danger')
        else:
            db = get_db()
            db.execute(
                'UPDATE users SET password_hash = ? WHERE id = ?',
                (generate_password_hash(new_password), current_user.id)
            )
            db.commit()
            flash('Пароль успешно изменён.', 'success')
            return redirect(url_for('index'))

    return render_template('change_password.html', errors=errors)

def create_app():
    with app.app_context():
        init_db()
    return app

create_app()

if __name__ == '__main__':
    app.run(debug=True)
