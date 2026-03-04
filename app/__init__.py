import os
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler
from flask import Flask, redirect, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, current_user
from config import Config
from sqlalchemy import inspect, text

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'


def _ensure_user_password_hash_size():
    if db.engine.dialect.name != 'mysql':
        return

    inspector = inspect(db.engine)

    if 'user' not in inspector.get_table_names():
        return

    for column in inspector.get_columns('user'):
        if column.get('name') == 'password_hash':
            current_len = getattr(column.get('type'), 'length', None)
            if current_len is not None and current_len < 255:
                db.session.execute(text("ALTER TABLE `user` MODIFY COLUMN password_hash VARCHAR(255)"))
                db.session.commit()
            return


def _ensure_user_role_column():
    inspector = inspect(db.engine)

    if 'user' not in inspector.get_table_names():
        return

    user_columns = {column.get('name') for column in inspector.get_columns('user')}

    if 'role' not in user_columns:
        if db.engine.dialect.name == 'mysql':
            db.session.execute(text(
                "ALTER TABLE `user` ADD COLUMN role VARCHAR(64) NOT NULL DEFAULT 'normal_user'"
            ))
        elif db.engine.dialect.name == 'sqlite':
            db.session.execute(text(
                "ALTER TABLE user ADD COLUMN role VARCHAR(64) DEFAULT 'normal_user'"
            ))
        else:
            return
        db.session.commit()

    if db.engine.dialect.name == 'mysql':
        db.session.execute(text(
            "UPDATE `user` SET role='normal_user' WHERE role IS NULL OR TRIM(role)=''"
        ))
        db.session.execute(text(
            "UPDATE `user` SET role='full_control' WHERE username='Admin'"
        ))
    else:
        db.session.execute(text(
            "UPDATE user SET role='normal_user' WHERE role IS NULL OR TRIM(role)=''"
        ))
        db.session.execute(text(
            "UPDATE user SET role='full_control' WHERE username='Admin'"
        ))
    db.session.commit()


def _ensure_user_mfa_columns():
    inspector = inspect(db.engine)

    if 'user' not in inspector.get_table_names():
        return

    user_columns = {column.get('name') for column in inspector.get_columns('user')}
    missing_columns = []
    for column_name, mysql_type, sqlite_type in [
        ('mfa_required', 'BOOLEAN NOT NULL DEFAULT 1', 'BOOLEAN DEFAULT 1'),
        ('mfa_enabled', 'BOOLEAN NOT NULL DEFAULT 0', 'BOOLEAN DEFAULT 0'),
        ('mfa_secret', 'VARCHAR(32) NULL', 'VARCHAR(32)'),
        ('mfa_created_at', 'DATETIME NULL', 'DATETIME'),
    ]:
        if column_name not in user_columns:
            missing_columns.append((column_name, mysql_type, sqlite_type))

    for column_name, mysql_type, sqlite_type in missing_columns:
        if db.engine.dialect.name == 'mysql':
            db.session.execute(text(f"ALTER TABLE `user` ADD COLUMN {column_name} {mysql_type}"))
        elif db.engine.dialect.name == 'sqlite':
            db.session.execute(text(f"ALTER TABLE user ADD COLUMN {column_name} {sqlite_type}"))

    if missing_columns:
        db.session.commit()

    if db.engine.dialect.name == 'mysql':
        db.session.execute(text(
            "UPDATE `user` SET mfa_required=1 WHERE mfa_required IS NULL"
        ))
        db.session.execute(text(
            "UPDATE `user` SET mfa_enabled=0 WHERE mfa_enabled IS NULL"
        ))
    else:
        db.session.execute(text(
            "UPDATE user SET mfa_required=1 WHERE mfa_required IS NULL"
        ))
        db.session.execute(text(
            "UPDATE user SET mfa_enabled=0 WHERE mfa_enabled IS NULL"
        ))
    db.session.commit()


def _ensure_user_password_policy_columns():
    inspector = inspect(db.engine)

    if 'user' not in inspector.get_table_names():
        return

    user_columns = {column.get('name') for column in inspector.get_columns('user')}
    missing_columns = []
    for column_name, mysql_type, sqlite_type in [
        ('must_change_password', 'BOOLEAN NOT NULL DEFAULT 0', 'BOOLEAN DEFAULT 0'),
        ('password_changed_at', 'DATETIME NULL', 'DATETIME'),
    ]:
        if column_name not in user_columns:
            missing_columns.append((column_name, mysql_type, sqlite_type))

    for column_name, mysql_type, sqlite_type in missing_columns:
        if db.engine.dialect.name == 'mysql':
            db.session.execute(text(f"ALTER TABLE `user` ADD COLUMN {column_name} {mysql_type}"))
        elif db.engine.dialect.name == 'sqlite':
            db.session.execute(text(f"ALTER TABLE user ADD COLUMN {column_name} {sqlite_type}"))

    if missing_columns:
        db.session.commit()

    if db.engine.dialect.name == 'mysql':
        db.session.execute(text(
            "UPDATE `user` SET must_change_password=0 WHERE must_change_password IS NULL"
        ))
        db.session.execute(text(
            "UPDATE `user` SET password_changed_at=UTC_TIMESTAMP() WHERE password_changed_at IS NULL"
        ))
    else:
        db.session.execute(text(
            "UPDATE user SET must_change_password=0 WHERE must_change_password IS NULL"
        ))
        db.session.execute(text(
            "UPDATE user SET password_changed_at=CURRENT_TIMESTAMP WHERE password_changed_at IS NULL"
        ))
    db.session.commit()


def _ensure_license_schema():
    inspector = inspect(db.engine)

    if 'license' not in inspector.get_table_names():
        return

    license_columns = {column.get('name') for column in inspector.get_columns('license')}
    missing_columns = []
    for column_name, mysql_type, sqlite_type in [
        ('purchase_date', 'DATE NULL', 'DATE'),
        ('expiry_date', 'DATE NULL', 'DATE'),
        ('amount_per_unit', 'DECIMAL(10,2) NULL', 'NUMERIC'),
        ('total_license', 'INT NULL', 'INTEGER'),
        ('remaining_license', 'INT NULL', 'INTEGER'),
        ('last_renewal_date', 'DATE NULL', 'DATE'),
    ]:
        if column_name not in license_columns:
            missing_columns.append((column_name, mysql_type, sqlite_type))

    for column_name, mysql_type, sqlite_type in missing_columns:
        if db.engine.dialect.name == 'mysql':
            db.session.execute(text(f"ALTER TABLE `license` ADD COLUMN {column_name} {mysql_type}"))
        elif db.engine.dialect.name == 'sqlite':
            db.session.execute(text(f"ALTER TABLE license ADD COLUMN {column_name} {sqlite_type}"))
    if missing_columns:
        db.session.commit()

    if db.engine.dialect.name == 'mysql':
        db.session.execute(text(
            "UPDATE `license` SET total_license = quantity WHERE total_license IS NULL"
        ))
        db.session.execute(text(
            "UPDATE `license` SET remaining_license = quantity WHERE remaining_license IS NULL"
        ))
    else:
        db.session.execute(text(
            "UPDATE license SET total_license = quantity WHERE total_license IS NULL"
        ))
        db.session.execute(text(
            "UPDATE license SET remaining_license = quantity WHERE remaining_license IS NULL"
        ))
    db.session.commit()


def _ensure_expense_schema():
    inspector = inspect(db.engine)

    if 'expense' not in inspector.get_table_names():
        return

    expense_columns = {column.get('name') for column in inspector.get_columns('expense')}
    missing_columns = []
    for column_name, mysql_type, sqlite_type in [
        ('category', "VARCHAR(50) NOT NULL DEFAULT 'others'", "VARCHAR(50)"),
        ('sub_category', "VARCHAR(100) NOT NULL DEFAULT 'others'", "VARCHAR(100)"),
        ('amount_usd', 'DECIMAL(12,2) NULL', 'NUMERIC'),
        ('remarks', 'TEXT NULL', 'TEXT'),
    ]:
        if column_name not in expense_columns:
            missing_columns.append((column_name, mysql_type, sqlite_type))

    for column_name, mysql_type, sqlite_type in missing_columns:
        if db.engine.dialect.name == 'mysql':
            db.session.execute(text(f"ALTER TABLE `expense` ADD COLUMN {column_name} {mysql_type}"))
        elif db.engine.dialect.name == 'sqlite':
            db.session.execute(text(f"ALTER TABLE expense ADD COLUMN {column_name} {sqlite_type}"))
    if missing_columns:
        db.session.commit()

    if db.engine.dialect.name == 'mysql':
        db.session.execute(text("UPDATE `expense` SET category='others' WHERE category IS NULL OR TRIM(category)=''"))
        db.session.execute(text("UPDATE `expense` SET sub_category='others' WHERE sub_category IS NULL OR TRIM(sub_category)=''"))
    else:
        db.session.execute(text("UPDATE expense SET category='others' WHERE category IS NULL OR TRIM(category)=''"))
        db.session.execute(text("UPDATE expense SET sub_category='others' WHERE sub_category IS NULL OR TRIM(sub_category)=''"))
    db.session.commit()


def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')
    app.config.update(
        SESSION_COOKIE_SAMESITE="None",
        SESSION_COOKIE_SECURE=True,
        REMEMBER_COOKIE_SAMESITE="None",
        REMEMBER_COOKIE_SECURE=True,
        WTF_CSRF_TIME_LIMIT=None,
    )
    try:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    except Exception as exc:
        app.logger.warning("ProxyFix not applied: %s", exc)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    # Set up logging
    if not os.path.exists('app/logs'):
        os.makedirs('app/logs')
    handler = RotatingFileHandler('app/logs/inventory_app.log', maxBytes=10000, backupCount=1)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)

    # Import blueprints and register them
    from app.routes.auth import auth as auth_blueprint
    from app.routes.main import main as main_blueprint
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(main_blueprint)

    @app.before_request
    def _enforce_security_policies():
        if not current_user.is_authenticated:
            return None

        endpoint = request.endpoint or ''
        if endpoint == 'static' or endpoint == 'auth.logout':
            return None

        max_age_days = app.config.get('PASSWORD_MAX_AGE_DAYS', 90)
        if current_user.is_password_change_required(max_age_days=max_age_days):
            if endpoint != 'main.change_password':
                return redirect(url_for('main.change_password'))
            return None

        if current_user.mfa_required and not current_user.has_mfa_configured:
            if endpoint != 'auth.mfa_setup':
                return redirect(url_for('auth.mfa_setup'))
            return None

        return None

    print(app.url_map)

    with app.app_context():
        # Import models here to avoid circular import issues
        from app.models import User

        # Create database tables
        db.create_all()
        _ensure_user_password_hash_size()
        _ensure_user_role_column()
        _ensure_user_mfa_columns()
        _ensure_user_password_policy_columns()
        _ensure_license_schema()
        _ensure_expense_schema()

        # Create users if they don't exist

        if not User.query.filter_by(username='Admin').first():
            Admin = User(username='Admin', role='full_control')
            Admin.set_password(os.getenv('ADMIN_PASSWORD', 'Admin@123'))
            Admin.must_change_password = False
            Admin.password_changed_at = datetime.utcnow()
            db.session.add(Admin)

        db.session.commit()

    return app

@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    return User.query.get(int(user_id))
