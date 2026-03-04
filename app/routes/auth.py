from datetime import datetime

import pyotp
from flask import Blueprint, current_app, flash, redirect, render_template, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
from app import db
from app.models import User
from app.forms import LoginForm, MFASetupForm, MFAVerifyForm, RegistrationForm

auth = Blueprint('auth', __name__)


def _normalize_otp(raw_otp):
    return ''.join(ch for ch in (raw_otp or '') if ch.isdigit())


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('mfa_user_id'):
        return redirect(url_for('auth.mfa_verify'))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            if user.has_mfa_configured:
                session['mfa_user_id'] = user.id
                return redirect(url_for('auth.mfa_verify'))
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('main.home'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    session.pop('mfa_user_id', None)
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(
            username=form.username.data,
            password_hash=hashed_password,
            must_change_password=True,
            password_changed_at=None,
            mfa_required=True,
            mfa_enabled=False,
            mfa_secret=None,
            mfa_created_at=None,
        )
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('register.html', title='Register', form=form)


@auth.route('/mfa/verify', methods=['GET', 'POST'])
def mfa_verify():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))

    mfa_user_id = session.get('mfa_user_id')
    user = User.query.get(mfa_user_id) if mfa_user_id else None

    if user is None:
        session.pop('mfa_user_id', None)
        flash('Please log in again.', 'warning')
        return redirect(url_for('auth.login'))

    if not user.has_mfa_configured:
        session.pop('mfa_user_id', None)
        flash('MFA is not configured for this user.', 'warning')
        return redirect(url_for('auth.login'))

    form = MFAVerifyForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(user.mfa_secret)
        otp_code = _normalize_otp(form.otp.data)
        if totp.verify(otp_code, valid_window=1):
            session.pop('mfa_user_id', None)
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('main.home'))
        flash('Invalid one-time password.', 'danger')

    return render_template('mfa_verify.html', form=form, username=user.username)


@auth.route('/mfa/setup', methods=['GET', 'POST'])
@login_required
def mfa_setup():
    form = MFASetupForm()

    if current_app.config.get('ENV') == 'development':
        valid_window = 2
    else:
        valid_window = 1

    if not current_user.mfa_secret:
        current_user.mfa_secret = pyotp.random_base32()
        db.session.commit()

    totp = pyotp.TOTP(current_user.mfa_secret)
    issuer = current_app.config.get('MFA_ISSUER_NAME', 'Inventory Management System')
    otpauth_url = totp.provisioning_uri(name=current_user.username, issuer_name=issuer)

    if not current_user.mfa_enabled and form.validate_on_submit():
        otp_code = _normalize_otp(form.otp.data)
        if totp.verify(otp_code, valid_window=valid_window):
            current_user.mfa_enabled = True
            if not current_user.mfa_created_at:
                current_user.mfa_created_at = datetime.utcnow()
            db.session.commit()
            flash('MFA enabled successfully.', 'success')
            return redirect(url_for('main.home'))
        flash('Invalid code. Please try again.', 'danger')

    return render_template(
        'mfa_setup.html',
        form=form,
        mfa_enabled=current_user.mfa_enabled,
        mfa_secret=current_user.mfa_secret,
        otpauth_url=otpauth_url,
    )
