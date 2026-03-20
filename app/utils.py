
import re
from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user

ROLE_RIGHTS = {
    'Администратор': {'create', 'edit_any', 'view_any', 'delete', 'view_logs'},
    'Пользователь': {'edit_self', 'view_self', 'view_logs'},
}

def get_rights(user):
    if not getattr(user, 'is_authenticated', False):
        return set()
    return ROLE_RIGHTS.get(getattr(user, 'role_name', None), set())

def has_right(user, action, target_user=None):
    rights = get_rights(user)
    if action == 'view_profile':
        return 'view_any' in rights or ('view_self' in rights and target_user and user.id == target_user['id'])
    if action == 'edit_user':
        return 'edit_any' in rights or ('edit_self' in rights and target_user and user.id == target_user['id'])
    if action == 'delete_user':
        return 'delete' in rights
    if action == 'create_user':
        return 'create' in rights
    if action == 'view_logs':
        return 'view_logs' in rights
    return False

def check_rights(action):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Для доступа к запрашиваемой странице необходимо пройти процедуру аутентификации.', 'warning')
                return redirect(url_for('login', next=url_for(func.__name__, **kwargs)))
            if action == 'view_logs':
                ok = has_right(current_user, 'view_logs')
            elif action == 'create_user':
                ok = has_right(current_user, 'create_user')
            else:
                ok = True
            if not ok:
                flash('У вас недостаточно прав для доступа к данной странице.', 'danger')
                return redirect(url_for('index'))
            return func(*args, **kwargs)
        return wrapper
    return decorator

def can_view_logs_query(user):
    if getattr(user, 'role_name', None) == 'Администратор':
        return '', []
    return 'WHERE user_id = ?', [user.id]

def validate_login(login):
    if not login:
        return 'Поле не может быть пустым.'
    if len(login) < 5:
        return 'Логин должен содержать не менее 5 символов.'
    if not re.fullmatch(r'[A-Za-z0-9]+', login):
        return 'Логин должен содержать только латинские буквы и цифры.'
    return None

def validate_name(value):
    if not value:
        return 'Поле не может быть пустым.'
    return None

def validate_password(password):
    if not password:
        return 'Поле не может быть пустым.'
    if len(password) < 8:
        return 'Пароль должен содержать не менее 8 символов.'
    if len(password) > 128:
        return 'Пароль должен содержать не более 128 символов.'
    if ' ' in password:
        return 'Пароль не должен содержать пробелы.'
    if not re.search(r'[A-ZА-ЯЁ]', password):
        return 'Пароль должен содержать хотя бы одну заглавную букву.'
    if not re.search(r'[a-zа-яё]', password):
        return 'Пароль должен содержать хотя бы одну строчную букву.'
    if not re.search(r'\d', password):
        return 'Пароль должен содержать хотя бы одну цифру.'
    allowed = r'[A-Za-zА-Яа-яЁё0-9~!?@#$%^&*_\-+()\[\]{}><\/\\|"\'\.,:;]+'
    if not re.fullmatch(allowed, password):
        return 'Пароль содержит недопустимые символы.'
    return None

def full_name(row):
    parts = [row.get('last_name') or '', row.get('first_name') or '', row.get('middle_name') or '']
    return ' '.join(p for p in parts if p).strip() or row.get('login', '')
