
import csv
import io
from flask import Blueprint, render_template, request, send_file
from flask_login import current_user
from app.db import get_db
from app.utils import check_rights, can_view_logs_query

reports_bp = Blueprint('reports', __name__, url_prefix='/reports')

@reports_bp.route('/visits')
@check_rights('view_logs')
def visits():
    db = get_db()
    page = max(request.args.get('page', 1, type=int), 1)
    per_page = 10
    where, params = can_view_logs_query(current_user)
    total = db.execute(
        f'''
        SELECT COUNT(*) as cnt
        FROM visit_logs vl
        {where}
        ''',
        params
    ).fetchone()['cnt']

    offset = (page - 1) * per_page
    rows = db.execute(
        f'''
        SELECT vl.id, vl.path, vl.created_at, vl.user_id,
               u.last_name, u.first_name, u.middle_name
        FROM visit_logs vl
        LEFT JOIN users u ON u.id = vl.user_id
        {where}
        ORDER BY vl.created_at DESC, vl.id DESC
        LIMIT ? OFFSET ?
        ''',
        params + [per_page, offset]
    ).fetchall()

    total_pages = max((total + per_page - 1) // per_page, 1)
    return render_template('reports/visits.html', rows=rows, page=page, total_pages=total_pages)

@reports_bp.route('/pages')
@check_rights('view_logs')
def pages_report():
    db = get_db()
    where, params = can_view_logs_query(current_user)
    rows = db.execute(
        f'''
        SELECT path, COUNT(*) AS visits_count
        FROM visit_logs
        {where}
        GROUP BY path
        ORDER BY visits_count DESC, path ASC
        '''
        , params
    ).fetchall()
    return render_template('reports/pages.html', rows=rows)

@reports_bp.route('/users')
@check_rights('view_logs')
def users_report():
    db = get_db()
    where, params = can_view_logs_query(current_user)
    rows = db.execute(
        f'''
        SELECT vl.user_id,
               CASE
                   WHEN vl.user_id IS NULL THEN 'Неаутентифицированный пользователь'
                   ELSE TRIM(COALESCE(u.last_name, '') || ' ' || COALESCE(u.first_name, '') || ' ' || COALESCE(u.middle_name, ''))
               END AS full_name,
               COUNT(*) AS visits_count
        FROM visit_logs vl
        LEFT JOIN users u ON u.id = vl.user_id
        {where}
        GROUP BY vl.user_id, full_name
        ORDER BY visits_count DESC, full_name ASC
        '''
        , params
    ).fetchall()
    return render_template('reports/users.html', rows=rows)

@reports_bp.route('/pages/export')
@check_rights('view_logs')
def export_pages_csv():
    db = get_db()
    where, params = can_view_logs_query(current_user)
    rows = db.execute(
        f'''
        SELECT path, COUNT(*) AS visits_count
        FROM visit_logs
        {where}
        GROUP BY path
        ORDER BY visits_count DESC, path ASC
        ''',
        params
    ).fetchall()
    return _csv_response('pages_report.csv', ['Страница', 'Количество посещений'],
                         [[r['path'], r['visits_count']] for r in rows])

@reports_bp.route('/users/export')
@check_rights('view_logs')
def export_users_csv():
    db = get_db()
    where, params = can_view_logs_query(current_user)
    rows = db.execute(
        f'''
        SELECT CASE
                   WHEN vl.user_id IS NULL THEN 'Неаутентифицированный пользователь'
                   ELSE TRIM(COALESCE(u.last_name, '') || ' ' || COALESCE(u.first_name, '') || ' ' || COALESCE(u.middle_name, ''))
               END AS full_name,
               COUNT(*) AS visits_count
        FROM visit_logs vl
        LEFT JOIN users u ON u.id = vl.user_id
        {where}
        GROUP BY vl.user_id, full_name
        ORDER BY visits_count DESC, full_name ASC
        ''',
        params
    ).fetchall()
    return _csv_response('users_report.csv', ['Пользователь', 'Количество посещений'],
                         [[r['full_name'], r['visits_count']] for r in rows])

def _csv_response(filename, headers, data_rows):
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=';')
    writer.writerow(headers)
    writer.writerows(data_rows)
    mem = io.BytesIO(buffer.getvalue().encode('utf-8-sig'))
    buffer.close()
    mem.seek(0)
    return send_file(mem, mimetype='text/csv', as_attachment=True, download_name=filename)
