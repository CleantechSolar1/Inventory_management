import io
from io import StringIO
import csv
from decimal import Decimal, InvalidOperation
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, Response
from flask_login import login_required, current_user
from app import db
from app.models import Inventory, Log, User, Repair, PreUser, RepairHistory
from app.forms import InventoryForm, RepairForm
from datetime import datetime, timedelta
from flask import render_template, redirect, url_for, request, flash
from app.forms import ResetPasswordForm, ChangePasswordForm  # Create this form as needed
from werkzeug.security import generate_password_hash
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask import current_app, flash, redirect, render_template, request, url_for
from collections import Counter
import logging
logging.basicConfig(level=logging.DEBUG)
from app.models import License, LicenseDetails, LicenseRenewal, Domain, DomainRenewal, Expense, ExpenseVendor, ExpenseBudget, db
from datetime import datetime
from sqlalchemy.exc import IntegrityError

# Define the main Blueprint
main = Blueprint('main', __name__)

# Dropdown options
ASSET_TYPES = ['Laptop', 'Monitor', 'Accessories', 'Printer']
STATUS = ['Available', 'Sold', 'In Use', 'Retired', 'Dead']
BRANDS = ['Lenovo', 'Dell', 'HP', 'Apple', 'ViewSonic', 'Samsung', 'Microsoft', 'LG', 'Fujitsu', 'Acer']
OPERATING_SYSTEMS = ['Windows', 'Mac', 'Linux']
DEPARTMENTS = ['IT', 'Procurement', 'Legal', 'Project', 'O&M', 'Finance', 'BD', 'HR', 'Wind', 'Risk', 'Engineering', 'Corporate', 'Administration', 'Infrastructure', 'HSSE & SP']
OFFICES = ['Mumbai', 'Pune', 'Delhi', 'Hyderabad', 'Chennai', 'Singapore', 'Thailand', 'Malaysia', 'Philippines', 'Vietnam', 'Cambodia', 'Indonesia', 'India']
COUNTRIES = ['Singapore', 'Thailand', 'Malaysia', 'Philippines', 'Vietnam', 'Cambodia', 'Indonesia', 'India']
VENDOR_LOCATIONS = ['Mumbai', 'Pune', 'Delhi', 'Hyderabad', 'Chennai', 'Singapore', 'Thailand', 'Malaysia', 'Philippines', 'Vietnam', 'Cambodia', 'Indonesia', 'India']

# Prefix Dictionaries
COUNTRY_CODES = {'Singapore': 'SG', 'India': 'IN', 'Thailand': 'TH', 'Malaysia':'MY', 'Philippines': 'PH', 'Vietnam': 'VN', 'Cambodia': 'KH', 'Indonesia': 'ID'}
ASSET_TYPE_CODES = {'Laptop': 'LT', 'Monitor': 'MN', 'Accessories': 'AC', 'Printer': 'PR'}
BRAND_CODES = {'Lenovo': 'LNV', 'Dell': 'DLL', 'HP': 'HPP', 'Apple': 'APL', 'ViewSonic': 'VWS', 'Samsung': 'SAM', 'Microsoft': 'MIS', 'LG': 'LGG', 'Fujitsu': 'FUJ', 'Acer': 'ACR'}


def block_read_only(action_message='perform this action', redirect_endpoint='main.home', **redirect_kwargs):
    if getattr(current_user, 'is_read_only', False):
        flash(f'Read-only users cannot {action_message}.', 'danger')
        return redirect(url_for(redirect_endpoint, **redirect_kwargs))
    return None


def parse_iso_date(value):
    if not value:
        return None
    return datetime.strptime(value, '%Y-%m-%d').date()


def log_user_activity(action, changes, item_id=None, serial_number=None):
    if not current_user.is_authenticated:
        return
    db.session.add(
        Log(
            user_id=current_user.id,
            action=action,
            item_id=item_id,
            serial_number=serial_number,
            changes=changes
        )
    )


def recalculate_remaining_license(license_obj):
    used = (
        db.session.query(db.func.coalesce(db.func.sum(LicenseDetails.quantity), 0))
        .filter(LicenseDetails.license_id == license_obj.id)
        .scalar()
        or 0
    )
    total = license_obj.total_license if license_obj.total_license is not None else license_obj.quantity
    total = total or 0
    license_obj.remaining_license = max(0, total - used)

@main.route('/', methods=['GET', 'POST'])
@login_required
def home():
    # Get all items from the inventory
    items_query = Inventory.query

    # Filters
    search_query = request.args.get('search_query', '')
    asset_type_filter = request.args.get('asset_type')
    department_filter = request.args.get('department')
    country_filter = request.args.get('country')
    status_filter = request.args.get('status')
    purchase_date_start = request.args.get('purchase_date_start')
    purchase_date_end = request.args.get('purchase_date_end')
    warranty_end_date_start = request.args.get('warranty_end_date_start')
    warranty_end_date_end = request.args.get('warranty_end_date_end')

    # Apply search query if provided
    if search_query:
        items_query = items_query.filter(
            Inventory.asset_tag.contains(search_query) |
            Inventory.brand.contains(search_query) |
            Inventory.model.contains(search_query) |
            Inventory.current_owner.contains(search_query) |
            Inventory.previous_owner.contains(search_query) |
            Inventory.serial_number.contains(search_query)
        )

    if asset_type_filter:
        items_query = items_query.filter_by(asset_type=asset_type_filter)
    if department_filter:
        items_query = items_query.filter_by(department=department_filter)
    if country_filter:
        items_query = items_query.filter_by(country=country_filter)
    if status_filter:
        items_query = items_query.filter_by(status=status_filter)
    if purchase_date_start:
        items_query = items_query.filter(Inventory.purchase_date >= datetime.strptime(purchase_date_start, '%Y-%m-%d'))
    if purchase_date_end:
        items_query = items_query.filter(Inventory.purchase_date <= datetime.strptime(purchase_date_end, '%Y-%m-%d'))
    if warranty_end_date_start:
        items_query = items_query.filter(Inventory.warranty_end_date >= datetime.strptime(warranty_end_date_start, '%Y-%m-%d'))
    if warranty_end_date_end:
        items_query = items_query.filter(Inventory.warranty_end_date <= datetime.strptime(warranty_end_date_end, '%Y-%m-%d'))

    # Pagination with 20 items per page
    page = request.args.get('page', 1, type=int)
    per_page = 20  # Number of items per page
    items = items_query.paginate(page=page, per_page=per_page, error_out=False)

    # Calculate brand counts
    brand_counts = Counter(item.brand for item in items.items)
    sorted_brand_counts = dict(sorted(brand_counts.items(), key=lambda x: x[1], reverse=True))

    # Calculate status counts
    status_counts = Counter(item.status for item in items.items)
    sorted_status_counts = dict(sorted(status_counts.items(), key=lambda x: x[1], reverse=True))

    # Total count of items
    total_count = items.total
    pre_users = PreUser.query.order_by(PreUser.name.asc()).all() if current_user.can_assign_assets else []

    # Aggregated data
    asset_type_counts = db.session.query(Inventory.asset_type, db.func.count(Inventory.id)).group_by(Inventory.asset_type).all()
    department_counts = db.session.query(Inventory.department, db.func.count(Inventory.id)).group_by(Inventory.department).all()
    country_counts = db.session.query(Inventory.country, db.func.count(Inventory.id)).group_by(Inventory.country).all()
    status_counts = db.session.query(Inventory.status, db.func.count(Inventory.id)).group_by(Inventory.status).all()

    # Prepare a clean dictionary of query parameters
    query_params = request.args.copy()
    query_params.pop('page', None)  # Remove 'page' if it exists

    return render_template(
        'home.html',
        items=items.items,
        asset_type_counts=asset_type_counts,
        department_counts=department_counts,
        country_counts=country_counts,
        status_counts=status_counts,
        asset_type_filter=asset_type_filter,
        department_filter=department_filter,
        country_filter=country_filter,
        purchase_date_start=purchase_date_start,
        purchase_date_end=purchase_date_end,
        warranty_end_date_start=warranty_end_date_start,
        warranty_end_date_end=warranty_end_date_end,
        pagination=items,
        query_params=query_params,
        asset_types=ASSET_TYPES,
        statuses=STATUS,
        brands=BRANDS,
        operating_systems=OPERATING_SYSTEMS,
        departments=DEPARTMENTS,
        offices=OFFICES,
        countries=COUNTRIES,
        vendor_locations=VENDOR_LOCATIONS,
        device_counts=sorted_brand_counts,
        sorted_status_counts=sorted_status_counts,
        total_count=total_count,
        search_query=search_query,
        pre_users=pre_users
    )

@main.route('/notifications')
@login_required
def notifications():
    today = datetime.today().date()
    warning_date = today + timedelta(days=30)

    expiring_assets = Inventory.query.filter(
        Inventory.warranty_end_date <= warning_date,
        Inventory.warranty_end_date >= today
    ).all()

    return render_template('notifications.html', expiring_assets=expiring_assets)

@main.route('/add', methods=['GET', 'POST'])
@login_required
def add_item():
    blocked_response = block_read_only('add items')
    if blocked_response:
        return blocked_response

    form = InventoryForm()
    form.asset_type.choices = [(at, at) for at in ASSET_TYPES]
    form.status.choices = [(st, st) for st in STATUS]
    form.brand.choices = [(br, br) for br in BRANDS]
    form.operating_system.choices = [(os, os) for os in OPERATING_SYSTEMS]
    form.department.choices = [(dp, dp) for dp in DEPARTMENTS]
    form.office.choices = [(of, of) for of in OFFICES]
    form.country.choices = [(ct, ct) for ct in COUNTRIES]
    form.vendor_location.choices = [(vl, vl) for vl in VENDOR_LOCATIONS]

    if form.validate_on_submit():
        try:
            # Check if serial number already exists
            existing_item = Inventory.query.filter_by(serial_number=form.serial_number.data).first()
            if existing_item:
                flash(f'An item with serial number {form.serial_number.data} already exists!', 'danger')
                return redirect(url_for('main.add_item'))
            
            # === Auto-generate asset_tag ===
            country_code = COUNTRY_CODES.get(form.country.data, 'XX')
            asset_type_code = ASSET_TYPE_CODES.get(form.asset_type.data, 'XX')
            brand_code = BRAND_CODES.get(form.brand.data, 'XXX')

            # Get the last numeric suffix used for this asset type
            last_asset = (
                Inventory.query
                .filter_by(asset_type=form.asset_type.data)
                .order_by(Inventory.id.desc())  # or order_by asset_tag if more appropriate
                .first()
            )

            # Extract numeric suffix
            START_NUMBER = 459  # fallback start number if no previous asset exists
            if last_asset:
                # Get last 4 digits of asset_tag
                try:
                    last_suffix = int(last_asset.asset_tag[-4:])
                except Exception:
                    last_suffix = START_NUMBER
            else:
                last_suffix = START_NUMBER

            # Next suffix
            next_suffix = last_suffix + 1
            serial_suffix = f"{next_suffix:04d}"

            generated_asset_tag = f"{country_code}{asset_type_code}{brand_code}{serial_suffix}"

            new_item = Inventory(
                asset_tag=generated_asset_tag,
                asset_type=form.asset_type.data,
                status=form.status.data,
                brand=form.brand.data,
                model=form.model.data,
                fa_code=form.fa_code.data,
                serial_number=form.serial_number.data,
                operating_system=form.operating_system.data,
                purchase_date=form.purchase_date.data,
                purchase_amount=form.purchase_amount.data,
                age=form.age.data,
                current_owner='IT',
                previous_owner=None,
                warranty_end_date=form.warranty_end_date.data,
                condition_notes=form.condition_notes.data,
                department=form.department.data,
                office=form.office.data,
                country=form.country.data,
                vendor_location=form.vendor_location.data,
                updated_by=current_user.username if current_user else "System",
                is_deleted=False,
                deleted_at=None,
                deleted_by=None
            )
            
            # Add the new item
            db.session.add(new_item)
            db.session.flush()  # This gets us the new item's ID before commit

            # Prepare item details for logging
            item_details = {
                'asset_tag': new_item.asset_tag,
                'asset_type': new_item.asset_type,
                'status': new_item.status,
                'brand': new_item.brand,
                'model': new_item.model,
                'serial_number': new_item.serial_number,
                'department': new_item.department,
                'current_owner': new_item.current_owner
            }

            # Create log entry with serial number
            log = Log(
                user_id=current_user.id,
                action="Added item",
                item_id=new_item.id,
                serial_number=new_item.serial_number,
                changes=f"User {current_user.username} added new item with details: {str(item_details)}"
            )
            
            db.session.add(log)
            db.session.commit()

            # Log success
            current_app.logger.info(
                f'User {current_user.username} added new item: {generated_asset_tag} '
                f'with serial number: {new_item.serial_number}'
            )
            
            flash(f'Item added successfully! Serial Number: {new_item.serial_number}', 'success')
            return redirect(url_for('main.home'))

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(
                f'Error adding item with serial number {form.serial_number.data}: {str(e)}',
                exc_info=True
            )
            flash(f'An error occurred while adding the item: {str(e)}. Please try again.', 'danger')
            
    elif request.method == 'POST':
        current_app.logger.warning(
            f'Form validation failed for user {current_user.username}: {form.errors}'
        )
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in {getattr(form, field).label.text}: {error}", 'danger')

    return render_template(
        'add_item.html',
        form=form,
        asset_types=ASSET_TYPES,
        statuses=STATUS,
        brands=BRANDS,
        operating_systems=OPERATING_SYSTEMS,
        departments=DEPARTMENTS,
        offices=OFFICES,
        countries=COUNTRIES,
        vendor_locations=VENDOR_LOCATIONS
    )

@main.route('/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    blocked_response = block_read_only('edit items')
    if blocked_response:
        return blocked_response

    item = Inventory.query.get_or_404(item_id)
    form = InventoryForm(obj=item)

    # Set form choices
    form.asset_type.choices = [(at, at) for at in ASSET_TYPES]
    form.status.choices = [(st, st) for st in STATUS]
    form.brand.choices = [(br, br) for br in BRANDS]
    form.operating_system.choices = [(os, os) for os in OPERATING_SYSTEMS]
    form.department.choices = [(dp, dp) for dp in DEPARTMENTS]
    form.office.choices = [(of, of) for of in OFFICES]
    form.country.choices = [(ct, ct) for ct in COUNTRIES]
    form.vendor_location.choices = [(vl, vl) for vl in VENDOR_LOCATIONS]

    if form.validate_on_submit():
        old_data = {field.name: getattr(item, field.name) for field in item.__table__.columns}
        
        # Allow all users to update regular fields
        form.populate_obj(item)

        # Allow only the Admin to update restricted fields
        if not current_user.is_elevated:
            item.model = old_data['model']
            item.fa_code = old_data['fa_code']
            item.serial_number = old_data['serial_number']

        item.updated_by = current_user.username

        # Detect changes
        changes = {}
        for field in item.__table__.columns:
            new_value = getattr(item, field.name)
            if old_data[field.name] != new_value:
                changes[field.name] = {'old': old_data[field.name], 'new': new_value}

        db.session.commit()

        # Log the update
        log = Log(
            user_id=current_user.id,
            action="Updated item",
            item_id=item.id,
            serial_number=item.serial_number,
            changes=str(changes)
        )
        db.session.add(log)
        db.session.commit()

        current_app.logger.info(f'{current_user.username} updated item: {item.asset_tag} with serial number: {item.serial_number}')
        flash('Item updated successfully!', 'success')
        return redirect(url_for('main.home'))

    return render_template(
        'edit_item.html',
        form=form,
        item=item,
        asset_types=ASSET_TYPES,
        statuses=STATUS,
        brands=BRANDS,
        operating_systems=OPERATING_SYSTEMS,
        departments=DEPARTMENTS,
        offices=OFFICES,
        countries=COUNTRIES,
        vendor_locations=VENDOR_LOCATIONS
    )


@main.route('/view_logs')
@login_required
def view_logs():
    # Get the filter parameter from the URL
    log_filter = request.args.get('filter', 'all')
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    page = request.args.get('page', 1, type=int)

    # Base query
    query = Log.query

    # Apply filter if specified
    if log_filter == 'csv_import':
        query = query.filter(Log.action == 'CSV Import')

    # Filter by date range if provided
    if start_date_str and end_date_str:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
            # Make end_date inclusive (end of day)
            end_date = end_date.replace(hour=23, minute=59, second=59)
            query = query.filter(Log.timestamp.between(start_date, end_date))
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.', 'danger')

    # Order logs by timestamp descending
    logs_pagination = query.order_by(Log.timestamp.desc()).paginate(page=page, per_page=50, error_out=False)
    logs = logs_pagination.items

    current_app.logger.info(f"Fetched {len(logs)} logs")
    for log in logs:
        current_app.logger.debug(f"Log: ID {log.id}, Action {log.action}, Item ID {log.item_id}, Changes {log.changes}")

    return render_template(
        'view_logs.html',
        logs=logs,
        logs_pagination=logs_pagination,
        current_filter=log_filter,
        start_date=start_date_str,
        end_date=end_date_str
    )


@main.route('/export_csv')
@login_required
def export_csv():
    # Fetch inventory items from the database
    items = Inventory.query.filter_by(is_deleted=False).all()

    
    # Create a CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header row
    writer.writerow([
        'Asset Tag', 'Asset Type', 'Status', 'Brand', 'Model',
        'FA Code', 'Serial Number', 'Operating System', 'Purchase Date',
        'Age', 'Current Owner', 'Previous Owner', 'Warranty End Date',
        'Condition Notes', 'Department', 'Office', 'Country', 'Vendor Location', 'Updated By'
    ])
    
    # Write data rows
    for item in items:
        writer.writerow([
            item.asset_tag, item.asset_type, item.status, item.brand, item.model,
            item.fa_code, item.serial_number, item.operating_system, item.purchase_date,
            item.age, item.current_owner, item.previous_owner, item.warranty_end_date,
            item.condition_notes, item.department, item.office, item.country, item.vendor_location, item.updated_by
        ])
    
    # Create a response object with CSV content
    output.seek(0)
    return Response(
        output,
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=inventory_data.csv"}
    )


@main.route('/export_logs_csv')
@login_required
def export_logs_csv():
    log_filter = request.args.get('filter', 'all')
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    query = Log.query

    # Apply action filter
    if log_filter == 'csv_import':
        query = query.filter(Log.action == 'CSV Import')

    if start_date_str and end_date_str:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
            end_date = end_date.replace(hour=23, minute=59, second=59)
            query = query.filter(Log.timestamp.between(start_date, end_date))
        except ValueError:
            flash('Invalid date format for export.', 'danger')

    logs = query.all()
    
    # Create a CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header row
    writer.writerow([
        'Timestamp', 'User ID', 'Username', 'Action', 'Item ID', 'Changes'
    ])
    
    # Write data rows
    for log in logs:
        username = User.query.get(log.user_id).username if log.user_id else 'Unknown'
        writer.writerow([
            log.timestamp,
            log.user_id,
            username,
            log.action,
            log.item_id,
            log.changes
        ])
    
    # Create a response object with CSV content
    output.seek(0)
    return Response(
        output,
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=logs_data.csv"}
    )


@main.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.can_add_users:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('main.home'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('main.add_user'))
        new_user = User(username=username, role=User.ROLE_NORMAL_USER)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        # Log the user addition
        log = Log(
            user_id=current_user.id,
            action="Added user",
            item_id=None,
            changes=f"Added user with username: {username}"
        )
        db.session.add(log)
        db.session.commit()
        
        flash('User added successfully.', 'success')
        return redirect(url_for('main.home'))
    
    return render_template('add_user.html')


@main.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.can_delete_users:
        flash('You do not have permission to delete users.', 'danger')
        return redirect(url_for('main.view_users'))

    user = User.query.get(user_id)
    if user and not user.is_super_admin:
        # Delete all logs related to this user
        logs = Log.query.filter_by(user_id=user_id).all()
        for log in logs:
            db.session.delete(log)
        
        db.session.delete(user)
        db.session.commit()
        
        flash('User deleted successfully.', 'success')
    else:
        flash('Superuser cannot be deleted.', 'error')
    
    return redirect(url_for('main.view_users'))


@main.route('/view_users')
@login_required
def view_users():
    if not current_user.can_manage_users:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('main.home'))

    users = User.query.all()
    return render_template('view_users.html', users=users)


@main.route('/set_user_access/<int:user_id>', methods=['POST'])
@login_required
def set_user_access(user_id):
    if not current_user.can_manage_users:
        flash('You do not have permission to manage user access.', 'danger')
        return redirect(url_for('main.home'))

    user = User.query.get_or_404(user_id)
    if user.is_super_admin:
        flash('Superuser access cannot be modified.', 'danger')
        return redirect(url_for('main.view_users'))

    new_role = request.form.get('role', User.ROLE_NORMAL_USER)
    allowed_roles = {
        User.ROLE_NORMAL_USER,
        User.ROLE_READ_ONLY,
        User.ROLE_FULL_CONTROL,
        User.ROLE_FULL_CONTROL_NO_DELETE,
        User.ROLE_FULL_CONTROL_NO_DELETE_NO_ADD_USER
    }
    if new_role not in allowed_roles:
        flash('Invalid access level selected.', 'danger')
        return redirect(url_for('main.view_users'))

    old_role = user.role
    user.role = new_role

    log = Log(
        user_id=current_user.id,
        action='Updated user access',
        item_id=None,
        changes=f'Updated access for {user.username}: {old_role} -> {new_role}'
    )
    db.session.add(log)
    db.session.commit()

    flash(f'Access updated for {user.username}.', 'success')
    return redirect(url_for('main.view_users'))


@main.route('/pre_users', methods=['GET', 'POST'])
@login_required
def manage_pre_users():
    if not current_user.can_add_users:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('main.home'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        department = request.form.get('department', '').strip() or None

        if not name:
            flash('Pre-user name is required.', 'danger')
            return redirect(url_for('main.manage_pre_users'))

        existing = PreUser.query.filter_by(name=name).first()
        if existing:
            flash('Pre-user already exists.', 'danger')
            return redirect(url_for('main.manage_pre_users'))

        new_pre_user = PreUser(name=name, department=department)
        db.session.add(new_pre_user)

        log = Log(
            user_id=current_user.id,
            action='Added pre-user',
            item_id=None,
            changes=f'Added pre-user: {name}'
        )
        db.session.add(log)
        db.session.commit()

        flash('Pre-user added successfully.', 'success')
        return redirect(url_for('main.manage_pre_users'))

    page = request.args.get('page', 1, type=int)
    pre_users_pagination = PreUser.query.order_by(PreUser.name.asc()).paginate(page=page, per_page=50, error_out=False)
    pre_users = pre_users_pagination.items
    return render_template('pre_users.html', pre_users=pre_users, pre_users_pagination=pre_users_pagination)


@main.route('/pre_users/import', methods=['POST'])
@login_required
def import_pre_users():
    if not current_user.can_add_users:
        flash('You do not have permission to import pre-users.', 'danger')
        return redirect(url_for('main.home'))

    file = request.files.get('file')
    if not file or not file.filename:
        flash('Please select a CSV file.', 'danger')
        return redirect(url_for('main.manage_pre_users'))

    try:
        stream = io.StringIO(file.stream.read().decode('utf-8-sig'), newline=None)
        rows = list(csv.reader(stream))
        if not rows:
            flash('CSV file is empty.', 'warning')
            return redirect(url_for('main.manage_pre_users'))

        start_index = 0
        header = [col.strip().lower() for col in rows[0]]
        if 'name' in header or 'department' in header:
            start_index = 1

        existing_names = {
            name for (name,) in db.session.query(PreUser.name).all()
        }
        seen_names = set()

        added_count = 0
        skipped_existing = 0
        skipped_invalid = 0

        for row in rows[start_index:]:
            if not row:
                skipped_invalid += 1
                continue

            name = (row[0] if len(row) > 0 else '').strip()
            department = (row[1] if len(row) > 1 else '').strip() or None

            if not name:
                skipped_invalid += 1
                continue

            if name in existing_names or name in seen_names:
                skipped_existing += 1
                continue

            db.session.add(PreUser(name=name, department=department))
            seen_names.add(name)
            added_count += 1

        log = Log(
            user_id=current_user.id,
            action='Bulk imported pre-users',
            item_id=None,
            changes=(
                f'Added={added_count}, Skipped Existing={skipped_existing}, '
                f'Skipped Invalid={skipped_invalid}'
            )
        )
        db.session.add(log)
        db.session.commit()

        flash(
            f'Pre-user import complete. Added: {added_count}, '
            f'Skipped existing: {skipped_existing}, Skipped invalid: {skipped_invalid}.',
            'success'
        )
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Error importing pre-users: {e}')
        flash('An error occurred while importing pre-users. Please check the CSV format.', 'danger')

    return redirect(url_for('main.manage_pre_users'))


@main.route('/pre_users/delete/<int:pre_user_id>', methods=['POST'])
@login_required
def delete_pre_user(pre_user_id):
    if not current_user.can_delete_users:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('main.home'))

    pre_user = PreUser.query.get_or_404(pre_user_id)
    pre_user_name = pre_user.name
    db.session.delete(pre_user)

    log = Log(
        user_id=current_user.id,
        action='Deleted pre-user',
        item_id=None,
        changes=f'Deleted pre-user: {pre_user_name}'
    )
    db.session.add(log)
    db.session.commit()

    flash('Pre-user deleted successfully.', 'success')
    return redirect(url_for('main.manage_pre_users'))


@main.route('/assign_owner/<int:item_id>', methods=['POST'])
@login_required
def assign_owner(item_id):
    if not current_user.can_assign_assets:
        flash('You do not have permission to assign assets.', 'danger')
        return redirect(url_for('main.home'))

    pre_user_id = request.form.get('pre_user_id', type=int)
    if not pre_user_id:
        flash('Please select a user to assign.', 'danger')
        return redirect(url_for('main.home'))

    pre_user = PreUser.query.get(pre_user_id)
    if not pre_user:
        flash('Selected pre-user does not exist.', 'danger')
        return redirect(url_for('main.home'))

    item = Inventory.query.get_or_404(item_id)
    old_owner = item.current_owner

    if old_owner == pre_user.name:
        flash(f'{item.asset_tag} is already assigned to {pre_user.name}.', 'info')
        return redirect(url_for('main.home'))

    item.previous_owner = old_owner
    item.current_owner = pre_user.name
    item.updated_by = current_user.username
    if pre_user.department:
        item.department = pre_user.department

    log = Log(
        user_id=current_user.id,
        action='Assigned asset',
        item_id=item.id,
        serial_number=item.serial_number,
        changes=f'Asset {item.asset_tag} reassigned from {old_owner} to {pre_user.name}'
    )
    db.session.add(log)
    db.session.commit()

    flash(f'{item.asset_tag} assigned to {pre_user.name}.', 'success')
    return redirect(url_for('main.home'))


@main.route('/asset_repairs/<int:item_id>', methods=['GET', 'POST'])
@login_required
def asset_repairs(item_id):
    item = Inventory.query.get_or_404(item_id)

    if request.method == 'POST':
        blocked_response = block_read_only('add repair entries', 'main.asset_repairs', item_id=item.id)
        if blocked_response:
            return blocked_response

        part = request.form.get('part', '').strip()
        issue_description = request.form.get('issue_description', '').strip() or None
        repair_date_raw = request.form.get('repair_date', '').strip()
        registered_date_raw = request.form.get('registered_date', '').strip()
        repaired_under_warranty = request.form.get('repaired_under_warranty', '').strip() or None
        remarks = request.form.get('remarks', '').strip() or None

        if not part:
            flash('Part is required.', 'danger')
            return redirect(url_for('main.asset_repairs', item_id=item.id))
        if not repair_date_raw:
            flash('Repair date is required.', 'danger')
            return redirect(url_for('main.asset_repairs', item_id=item.id))

        try:
            repair_date = datetime.strptime(repair_date_raw, '%Y-%m-%d').date()
            registered_date = (
                datetime.strptime(registered_date_raw, '%Y-%m-%d').date()
                if registered_date_raw else datetime.utcnow().date()
            )
        except ValueError:
            flash('Invalid date format. Use YYYY-MM-DD.', 'danger')
            return redirect(url_for('main.asset_repairs', item_id=item.id))

        repair_entry = RepairHistory(
            inventory_id=item.id,
            asset_tag=item.asset_tag,
            serial_number=item.serial_number,
            part=part,
            issue_description=issue_description,
            repair_date=repair_date,
            registered_date=registered_date,
            repaired_under_warranty=repaired_under_warranty,
            remarks=remarks,
            created_by=current_user.username
        )
        db.session.add(repair_entry)

        log = Log(
            user_id=current_user.id,
            action='Added repair',
            item_id=item.id,
            serial_number=item.serial_number,
            changes=f'Repair added for {item.asset_tag}: part={part}, warranty={repaired_under_warranty or "N/A"}'
        )
        db.session.add(log)
        db.session.commit()

        flash('Repair entry added successfully.', 'success')
        return redirect(url_for('main.asset_repairs', item_id=item.id))

    repairs = (
        RepairHistory.query
        .filter_by(inventory_id=item.id)
        .order_by(RepairHistory.repair_date.desc(), RepairHistory.id.desc())
        .all()
    )
    return render_template('asset_repairs.html', item=item, repairs=repairs)


@main.route('/reset_password/<int:user_id>', methods=['GET', 'POST'])
@login_required
def reset_password(user_id):
    if not current_user.can_manage_users:
        flash('You do not have permission to reset passwords.', 'danger')
        return redirect(url_for('main.home'))

    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        form = ResetPasswordForm(request.form)
        if form.validate():
            user.password_hash = generate_password_hash(form.new_password.data)
            db.session.commit()
            flash('Password reset successfully!', 'success')
            return redirect(url_for('main.view_users'))
        else:
            flash('Error resetting password. Please try again.', 'danger')
    else:
        form = ResetPasswordForm()
    return render_template('reset_password.html', form=form, user=user)

@main.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash('Current password is incorrect.', 'danger')
            return render_template('change_password.html', form=form)

        if form.current_password.data == form.new_password.data:
            flash('New password must be different from current password.', 'danger')
            return render_template('change_password.html', form=form)

        current_user.set_password(form.new_password.data)
        log_user_activity('Password changed', f'username={current_user.username}')
        db.session.commit()
        flash('Password changed successfully.', 'success')
        return redirect(url_for('main.home'))

    return render_template('change_password.html', form=form)

@main.route('/import_csv', methods=['GET', 'POST'])
@login_required
def import_csv():
    blocked_response = block_read_only('import CSV data')
    if blocked_response:
        return blocked_response

    if request.method == 'POST':
        file = request.files['file']
        if not file:
            flash('No file selected!', 'danger')
            return redirect(request.url)

        try:
            # Read the CSV file
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_input = csv.reader(stream)

            # Skip the header row if your CSV file has one
            next(csv_input, None)

            # Count imported rows
            imported_count = 0

            # Function to parse dates flexibly
            def parse_date(date_string):
                if not date_string or not str(date_string).strip():
                    return None
                date_formats = ['%Y-%m-%d', '%d-%m-%Y', '%m-%d-%Y']
                for date_format in date_formats:
                    try:
                        return datetime.strptime(str(date_string).strip(), date_format)
                    except ValueError:
                        continue
                raise ValueError(f"Unable to parse date: {date_string}")

            def parse_decimal(value):
                if value is None:
                    return None
                cleaned = str(value).strip().replace(',', '')
                if cleaned == '':
                    return None
                try:
                    return Decimal(cleaned)
                except InvalidOperation:
                    raise ValueError(f"Invalid numeric value: {value}")

            def parse_int(value):
                cleaned = '' if value is None else str(value).strip()
                if cleaned == '':
                    return None
                try:
                    return int(cleaned)
                except ValueError:
                    raise ValueError(f"Invalid integer value: {value}")

            # Iterate over the CSV rows
            for row_num, row in enumerate(csv_input, start=2):
                if not row or all(not str(col).strip() for col in row):
                    continue

                # Supports both CSV layouts:
                # 20 cols (legacy extra column after purchase_amount)
                # 19 cols (current)
                if len(row) < 19:
                    raise ValueError(f"Row {row_num} has {len(row)} columns; expected at least 19.")

                has_legacy_extra_col = len(row) >= 20
                shift = 1 if has_legacy_extra_col else 0

                age_index = 10 + shift
                current_owner_index = 11 + shift
                previous_owner_index = 12 + shift
                warranty_index = 13 + shift
                condition_notes_index = 14 + shift
                department_index = 15 + shift
                office_index = 16 + shift
                country_index = 17 + shift
                vendor_location_index = 18 + shift
                purchase_date_parsed = parse_date(row[8])
                warranty_date_parsed = parse_date(row[warranty_index])
                purchase_amount_value = parse_decimal(row[9])

                new_item = Inventory(
                    asset_tag=row[0].strip(),
                    asset_type=row[1].strip(),
                    status=row[2].strip(),
                    brand=row[3].strip(),
                    model=row[4].strip(),
                    fa_code=row[5].strip(),
                    serial_number=row[6].strip(),
                    operating_system=row[7].strip(),
                    purchase_date=purchase_date_parsed,
                    purchase_amount=purchase_amount_value,
                    age=parse_int(row[age_index]),
                    current_owner=row[current_owner_index].strip(),
                    previous_owner=row[previous_owner_index].strip() if row[previous_owner_index] else None,
                    warranty_end_date=warranty_date_parsed,
                    condition_notes=row[condition_notes_index].strip() if row[condition_notes_index] else None,
                    department=row[department_index].strip() if row[department_index] else None,
                    office=row[office_index].strip() if row[office_index] else None,
                    country=row[country_index].strip() if row[country_index] else None,
                    vendor_location=row[vendor_location_index].strip() if row[vendor_location_index] else None,
                    updated_by=current_user.username
                )
                db.session.add(new_item)
                imported_count += 1

            db.session.commit()

            # Log the import activity
            log_entry = Log(
                action="CSV Import",
                item_id=None,
                changes=f"Imported {imported_count} items",
                user_id=current_user.id
            )
            db.session.add(log_entry)
            db.session.commit()

            flash(f'CSV file imported successfully! {imported_count} items added.', 'success')
            return redirect(url_for('main.home'))

        except ValueError as e:
            db.session.rollback()
            current_app.logger.error(f'Error importing CSV file: {e}')
            flash(f'An error occurred while importing the file: {e}. Please check the date format and try again.', 'danger')
            return redirect(request.url)
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f'Error importing CSV file: {e}')
            flash('An unexpected error occurred while importing the file. Please check the format and try again.', 'danger')
            return redirect(request.url)
    
    return render_template('import_csv.html')
    
    
@main.route('/device_count', methods=['GET'])
@login_required
def device_count():
    # Get all items
    items = Inventory.query.all()

    # Calculate brand & status counts
    brand_counts = Counter(item.brand for item in items)
    status_counts = Counter(item.status for item in items)

    # Calculate asset type & country counts
    asset_type_counts = Counter(item.asset_type for item in items)
    country_counts = Counter(item.country for item in items)

    # Sort counts in descending order
    sorted_brand_counts = dict(sorted(brand_counts.items(), key=lambda x: x[1], reverse=True))
    sorted_status_counts = dict(sorted(status_counts.items(), key=lambda x: x[1], reverse=True))
    sorted_asset_type_counts = dict(sorted(asset_type_counts.items(), key=lambda x: x[1], reverse=True))
    sorted_country_counts = dict(sorted(country_counts.items(), key=lambda x: x[1], reverse=True))

    # Total count of items
    total_count = len(items)

    return render_template('device_count.html',
                           brand_counts=sorted_brand_counts,
                           status_counts=sorted_status_counts,
                           asset_type_counts=sorted_asset_type_counts,
                           country_counts=sorted_country_counts,
                           total_count=total_count)


@main.route('/delete/<int:item_id>', methods=['POST'])
@login_required
def delete_item(item_id):
    # Check if the user has admin permissions
    if not current_user.can_delete_items:
        flash("You do not have permission to delete items.", "danger")
        return redirect(url_for('main.home'))

    # Retrieve the item to be deleted
    item = Inventory.query.get_or_404(item_id)

    try:
        # Log deletion details before deleting the item
        delete_log = Log(
            user_id=current_user.id,
            action="Deleted item",
            item_id=item_id,
            serial_number=item.serial_number,
            changes=f"Deleted item with asset tag: {item.asset_tag}, type: {item.asset_type}"
        )
        db.session.add(delete_log)

        # Physically delete the item from the database
        db.session.delete(item)

        # Commit both the log and the deletion
        db.session.commit()

        flash('Item deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Error deleting item: {e}')
        flash('An error occurred while deleting the item. Please try again.', 'danger')

    return redirect(url_for('main.home'))


@main.route('/delete_all', methods=['POST'])
@login_required
def delete_all_items():
    # Check if the user has admin permissions
    if not current_user.can_delete_items:
        flash("You do not have permission to delete all items.", "danger")
        return redirect(url_for('main.home'))

    try:
        # Get all items before deletion for logging purposes
        all_items = Inventory.query.all()
        item_count = len(all_items)

        # Log deletion for each item individually to preserve serial numbers
        for item in all_items:
            delete_log = Log(
                user_id=current_user.id,
                action="Bulk deletion",
                item_id=item.id,
                serial_number=item.serial_number,
                changes=f"Item deleted by {current_user.username} during bulk deletion: Asset Tag: {item.asset_tag}, Type: {item.asset_type}, Brand: {item.brand}, Model: {item.model}",
                timestamp=datetime.utcnow()
            )
            db.session.add(delete_log)

        # Physically delete all items from the inventory
        for item in all_items:
            db.session.delete(item)

        # Commit the changes
        db.session.commit()

        current_app.logger.info(f'User {current_user.username} deleted all items ({item_count} items)')
        flash(f'All items ({item_count}) have been deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Error deleting all items: {e}')
        flash('An error occurred while deleting all items. Please try again.', 'danger')

    return redirect(url_for('main.home'))

from flask import render_template, request, redirect, url_for, flash
from app.models import License, LicenseDetails, LicenseRenewal, Domain, DomainRenewal, db


@main.route('/licenses', methods=['GET'])
@login_required
def licenses():
    licenses_list = License.query.order_by(License.name.asc()).all()
    return render_template('licenses.html', licenses=licenses_list)


@main.route('/license/<int:license_id>', methods=['GET', 'POST'])
@login_required
def license_details(license_id):
    license = License.query.get_or_404(license_id)

    if request.method == 'POST':
        blocked_response = block_read_only('add license details/renewals', 'main.license_details', license_id=license_id)
        if blocked_response:
            return blocked_response

        form_type = request.form.get('form_type', 'detail')
        if form_type == 'renewal':
            renewal_date = parse_iso_date(request.form.get('renewal_date'))
            amount = request.form.get('amount')
            remarks = request.form.get('remarks')
            if not renewal_date:
                flash('Renewal date is required.', 'danger')
                return redirect(url_for('main.license_details', license_id=license_id))

            renewal = LicenseRenewal(
                license_id=license.id,
                renewal_date=renewal_date,
                amount=Decimal(amount) if amount else None,
                remarks=remarks
            )
            license.last_renewal_date = renewal_date
            license.expiry_date = renewal_date
            db.session.add(renewal)
            log_user_activity('License renewal added', f'License={license.name}, renewal_date={renewal_date}, amount={amount or "N/A"}')
            db.session.commit()
            flash('License renewal recorded successfully.', 'success')
            return redirect(url_for('main.license_details', license_id=license_id))

        current_owner = request.form.get('current_owner')
        purchase_date = request.form.get('purchase_date')
        expiry_date = request.form.get('expiry_date')
        remarks = request.form.get('remarks', '')
        quantity = int(request.form.get('quantity', 1) or 1)

        if not current_owner or not purchase_date or not expiry_date or quantity <= 0:
            flash('Owner, purchase date, expiry date and quantity are required.', 'danger')
            return redirect(url_for('main.license_details', license_id=license_id))

        new_detail = LicenseDetails(
            license_id=license_id,
            current_owner=current_owner,
            purchase_date=parse_iso_date(purchase_date),
            expiry_date=parse_iso_date(expiry_date),
            quantity=quantity,
            remarks=remarks
        )
        db.session.add(new_detail)
        recalculate_remaining_license(license)
        log_user_activity('License detail added', f'License={license.name}, owner={current_owner}, quantity={quantity}, expiry={expiry_date}')
        db.session.commit()
        flash("License detail added successfully.", "success")
        return redirect(url_for('main.license_details', license_id=license_id))

    details = LicenseDetails.query.filter_by(license_id=license_id).all()
    renewals = LicenseRenewal.query.filter_by(license_id=license_id).order_by(LicenseRenewal.renewal_date.desc()).all()
    used_count = sum((d.quantity or 0) for d in details)
    total_count = license.total_license if license.total_license is not None else (license.quantity or 0)
    missing_details_count = max(0, total_count - used_count)

    return render_template(
        'license_details.html',
        license=license,
        details=details,
        renewals=renewals,
        required_details=missing_details_count,
        missing_details_count=missing_details_count
    )


@main.route('/add_license', methods=['GET', 'POST'])
@login_required
def add_license():
    blocked_response = block_read_only('add licenses')
    if blocked_response:
        return blocked_response

    if request.method == 'POST':
        try:
            name = request.form.get('name')
            license_type = request.form.get('type')
            purchase_date = parse_iso_date(request.form.get('purchase_date'))
            expiry_date = parse_iso_date(request.form.get('expiry_date'))
            amount_per_unit = request.form.get('amount_per_unit')
            total_license = int(request.form.get('total_license', 0) or 0)
            remaining_license = int(request.form.get('remaining_license', total_license) or total_license)

            if not name or not license_type or not purchase_date or not expiry_date or total_license <= 0:
                flash("Name, type, purchase/expiry date and total license are required.", "warning")
                return redirect(url_for('main.add_license'))

            new_license = License(
                name=name,
                type=license_type,
                quantity=total_license,
                purchase_date=purchase_date,
                expiry_date=expiry_date,
                amount_per_unit=Decimal(amount_per_unit) if amount_per_unit else None,
                total_license=total_license,
                remaining_license=max(0, remaining_license)
            )
            db.session.add(new_license)
            log_user_activity('License created', f'License={name}, total={total_license}, remaining={remaining_license}, expiry={expiry_date}')
            db.session.commit()
            flash("License added successfully!", "success")
            return redirect(url_for('main.licenses'))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error adding license: {e}")
            flash("An error occurred while adding the license.", "danger")
            return redirect(url_for('main.add_license'))
    return render_template('add_license.html')


@main.route('/edit_license/<int:license_id>', methods=['GET', 'POST'])
@login_required
def edit_license(license_id):
    blocked_response = block_read_only('edit licenses')
    if blocked_response:
        return blocked_response

    license = License.query.get_or_404(license_id)
    if request.method == 'POST':
        license.name = request.form.get('name')
        license.type = request.form.get('type')
        license.purchase_date = parse_iso_date(request.form.get('purchase_date'))
        license.expiry_date = parse_iso_date(request.form.get('expiry_date'))
        license.amount_per_unit = Decimal(request.form.get('amount_per_unit')) if request.form.get('amount_per_unit') else None
        license.total_license = int(request.form.get('total_license', 0) or 0)
        license.quantity = license.total_license
        recalculate_remaining_license(license)
        log_user_activity('License updated', f'License={license.name}, total={license.total_license}, remaining={license.remaining_license}, expiry={license.expiry_date}')
        db.session.commit()
        flash('License updated successfully!', 'success')
        return redirect(url_for('main.licenses'))
    return render_template('edit_license.html', license=license)


@main.route('/delete_license/<int:license_id>', methods=['POST'])
@login_required
def delete_license(license_id):
    blocked_response = block_read_only('delete licenses')
    if blocked_response:
        return blocked_response

    license = License.query.get_or_404(license_id)
    log_user_activity('License deleted', f'License={license.name}')
    db.session.delete(license)
    db.session.commit()
    flash('License deleted successfully!', 'success')
    return redirect(url_for('main.licenses'))


@main.route('/add_license_details/<int:license_id>', methods=['GET', 'POST'])
@login_required
def add_license_details(license_id):
    blocked_response = block_read_only('add license details')
    if blocked_response:
        return blocked_response

    license = License.query.get_or_404(license_id)
    if request.method == 'POST':
        current_owner = request.form.get('current_owner')
        purchase_date = request.form.get('purchase_date')
        expiry_date = request.form.get('expiry_date')
        remarks = request.form.get('remarks')
        quantity = int(request.form.get('quantity', 1) or 1)

        new_detail = LicenseDetails(
            license_id=license_id,
            current_owner=current_owner,
            purchase_date=parse_iso_date(purchase_date),
            expiry_date=parse_iso_date(expiry_date),
            quantity=quantity,
            remarks=remarks
        )
        db.session.add(new_detail)
        recalculate_remaining_license(license)
        log_user_activity('License detail added', f'License={license.name}, owner={current_owner}, quantity={quantity}')
        db.session.commit()
        flash('License details added successfully!')
        return redirect(url_for('main.license_details', license_id=license_id))
    return render_template('add_license_details.html', license=license)


@main.route('/edit_license_detail/<int:detail_id>', methods=['GET', 'POST'])
@login_required
def edit_license_detail(detail_id):
    blocked_response = block_read_only('edit license details')
    if blocked_response:
        return blocked_response

    detail = LicenseDetails.query.get_or_404(detail_id)
    if request.method == 'POST':
        detail.current_owner = request.form.get('current_owner')
        detail.purchase_date = parse_iso_date(request.form.get('purchase_date'))
        detail.expiry_date = parse_iso_date(request.form.get('expiry_date'))
        detail.quantity = int(request.form.get('quantity', detail.quantity or 1) or 1)
        detail.remarks = request.form.get('remarks')
        recalculate_remaining_license(detail.license)
        log_user_activity('License detail updated', f'License={detail.license.name}, owner={detail.current_owner}, quantity={detail.quantity}')
        db.session.commit()
        flash('License detail updated successfully!', 'success')
        return redirect(url_for('main.license_details', license_id=detail.license_id))
    return render_template('edit_license_detail.html', detail=detail)


@main.route('/delete_license_detail/<int:detail_id>', methods=['POST'])
@login_required
def delete_license_detail(detail_id):
    blocked_response = block_read_only('delete license details')
    if blocked_response:
        return blocked_response

    detail = LicenseDetails.query.get_or_404(detail_id)
    license_name = detail.license.name
    license_id = detail.license_id
    db.session.delete(detail)
    recalculate_remaining_license(detail.license)
    log_user_activity('License detail deleted', f'License={license_name}')
    db.session.commit()
    flash('License detail deleted successfully!', 'success')
    return redirect(url_for('main.license_details', license_id=license_id))


@main.route('/domains', methods=['GET'])
@login_required
def domains():
    domains_list = Domain.query.order_by(Domain.domain.asc()).all()
    return render_template('domains.html', domains=domains_list)


@main.route('/domains/add', methods=['GET', 'POST'])
@login_required
def add_domain():
    blocked_response = block_read_only('add domains')
    if blocked_response:
        return blocked_response

    if request.method == 'POST':
        domain_name = request.form.get('domain', '').strip()
        purchase_date = parse_iso_date(request.form.get('purchase_date'))
        renewal_date = parse_iso_date(request.form.get('renewal_date'))
        country = request.form.get('country')
        amount = request.form.get('amount')

        if not domain_name or not purchase_date or not renewal_date:
            flash('Domain, purchase date, and renewal date are required.', 'danger')
            return redirect(url_for('main.add_domain'))

        new_domain = Domain(
            domain=domain_name,
            purchase_date=purchase_date,
            renewal_date=renewal_date,
            country=country,
            amount=Decimal(amount) if amount else None
        )
        db.session.add(new_domain)
        log_user_activity('Domain created', f'Domain={domain_name}, renewal_date={renewal_date}')
        db.session.commit()
        flash('Domain added successfully.', 'success')
        return redirect(url_for('main.domains'))

    return render_template('add_domain.html')


@main.route('/domains/<int:domain_id>', methods=['GET', 'POST'])
@login_required
def domain_details(domain_id):
    domain = Domain.query.get_or_404(domain_id)

    if request.method == 'POST':
        blocked_response = block_read_only('add domain renewals', 'main.domain_details', domain_id=domain_id)
        if blocked_response:
            return blocked_response

        renewal_date = parse_iso_date(request.form.get('renewal_date'))
        amount = request.form.get('amount')
        remarks = request.form.get('remarks')
        if not renewal_date:
            flash('Renewal date is required.', 'danger')
            return redirect(url_for('main.domain_details', domain_id=domain_id))

        renewal = DomainRenewal(
            domain_id=domain.id,
            renewal_date=renewal_date,
            amount=Decimal(amount) if amount else None,
            remarks=remarks
        )
        domain.last_renewal_date = renewal_date
        domain.renewal_date = renewal_date
        db.session.add(renewal)
        log_user_activity('Domain renewal added', f'Domain={domain.domain}, renewal_date={renewal_date}, amount={amount or "N/A"}')
        db.session.commit()
        flash('Domain renewal added successfully.', 'success')
        return redirect(url_for('main.domain_details', domain_id=domain_id))

    renewals = DomainRenewal.query.filter_by(domain_id=domain.id).order_by(DomainRenewal.renewal_date.desc()).all()
    return render_template('domain_details.html', domain=domain, renewals=renewals)


@main.route('/domains/edit/<int:domain_id>', methods=['GET', 'POST'])
@login_required
def edit_domain(domain_id):
    blocked_response = block_read_only('edit domains')
    if blocked_response:
        return blocked_response

    domain = Domain.query.get_or_404(domain_id)
    if request.method == 'POST':
        domain.domain = request.form.get('domain', '').strip()
        domain.purchase_date = parse_iso_date(request.form.get('purchase_date'))
        domain.renewal_date = parse_iso_date(request.form.get('renewal_date'))
        domain.country = request.form.get('country')
        domain.amount = Decimal(request.form.get('amount')) if request.form.get('amount') else None
        log_user_activity('Domain updated', f'Domain={domain.domain}, renewal_date={domain.renewal_date}')
        db.session.commit()
        flash('Domain updated successfully.', 'success')
        return redirect(url_for('main.domains'))
    return render_template('edit_domain.html', domain=domain)


@main.route('/domains/delete/<int:domain_id>', methods=['POST'])
@login_required
def delete_domain(domain_id):
    blocked_response = block_read_only('delete domains')
    if blocked_response:
        return blocked_response

    domain = Domain.query.get_or_404(domain_id)
    log_user_activity('Domain deleted', f'Domain={domain.domain}')
    db.session.delete(domain)
    db.session.commit()
    flash('Domain deleted successfully.', 'success')
    return redirect(url_for('main.domains'))


@main.route('/expenses', methods=['GET'])
@login_required
def expenses():
    query = Expense.query

    search_name = request.args.get('name', '').strip()
    invoice_month = request.args.get('invoice_month', type=int)
    invoice_year = request.args.get('invoice_year', type=int)
    vendor = request.args.get('vendor', '').strip()
    cleantech_entity = request.args.get('cleantech_entity', '').strip()

    if search_name:
        query = query.filter(Expense.name.ilike(f'%{search_name}%'))
    if invoice_month:
        query = query.filter(Expense.invoice_month == invoice_month)
    if invoice_year:
        query = query.filter(Expense.invoice_year == invoice_year)
    if vendor:
        query = query.filter(Expense.vendor.ilike(f'%{vendor}%'))
    if cleantech_entity:
        query = query.filter(Expense.cleantech_entity.ilike(f'%{cleantech_entity}%'))

    expenses_list = query.order_by(Expense.payment_date.desc(), Expense.created_at.desc()).all()

    year_totals_raw = (
        db.session.query(
            Expense.invoice_year,
            db.func.coalesce(db.func.sum(Expense.amount_usd), 0)
        )
        .filter(Expense.is_void.is_(False))
        .group_by(Expense.invoice_year)
        .all()
    )
    year_expense_totals = {int(year): total for year, total in year_totals_raw if year is not None}

    budgets = ExpenseBudget.query.order_by(ExpenseBudget.year.desc()).all()
    budget_map = {budget.year: budget.total_budget_usd for budget in budgets}
    all_years = sorted(set(year_expense_totals.keys()) | set(budget_map.keys()), reverse=True)

    return render_template(
        'expenses.html',
        expenses=expenses_list,
        year_expense_totals=year_expense_totals,
        budgets=budgets,
        budget_map=budget_map,
        all_years=all_years
    )


@main.route('/expenses/export_csv', methods=['GET'])
@login_required
def export_expenses_csv():
    query = Expense.query

    search_name = request.args.get('name', '').strip()
    invoice_month = request.args.get('invoice_month', type=int)
    invoice_year = request.args.get('invoice_year', type=int)
    vendor = request.args.get('vendor', '').strip()
    cleantech_entity = request.args.get('cleantech_entity', '').strip()

    if search_name:
        query = query.filter(Expense.name.ilike(f'%{search_name}%'))
    if invoice_month:
        query = query.filter(Expense.invoice_month == invoice_month)
    if invoice_year:
        query = query.filter(Expense.invoice_year == invoice_year)
    if vendor:
        query = query.filter(Expense.vendor.ilike(f'%{vendor}%'))
    if cleantech_entity:
        query = query.filter(Expense.cleantech_entity.ilike(f'%{cleantech_entity}%'))

    expenses_list = query.order_by(Expense.payment_date.desc(), Expense.created_at.desc()).all()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'category', 'sub_category', 'name', 'payment_date', 'invoice_month', 'invoice_year',
        'vendor', 'cleantech_entity', 'invoice_date', 'currency', 'amount', 'amount_usd',
        'payment_mode', 'remarks', 'created_by', 'created_at', 'is_void', 'void_remarks',
        'voided_by', 'voided_at'
    ])

    for expense in expenses_list:
        writer.writerow([
            expense.category,
            expense.sub_category,
            expense.name,
            expense.payment_date.strftime('%Y-%m-%d') if expense.payment_date else '',
            expense.invoice_month,
            expense.invoice_year,
            expense.vendor,
            expense.cleantech_entity,
            expense.invoice_date.strftime('%Y-%m-%d') if expense.invoice_date else '',
            expense.currency,
            expense.amount,
            expense.amount_usd if expense.amount_usd is not None else '',
            expense.payment_mode,
            expense.remarks or '',
            expense.created_by,
            expense.created_at.strftime('%Y-%m-%d %H:%M:%S') if expense.created_at else '',
            int(bool(expense.is_void)),
            expense.void_remarks or '',
            expense.voided_by or '',
            expense.voided_at.strftime('%Y-%m-%d %H:%M:%S') if expense.voided_at else ''
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=expenses.csv'}
    )


@main.route('/expenses/import_csv', methods=['GET', 'POST'])
@login_required
def import_expenses_csv():
    blocked_response = block_read_only('import expenses')
    if blocked_response:
        return blocked_response

    if request.method == 'POST':
        file = request.files.get('file')
        if not file:
            flash('No file selected.', 'danger')
            return redirect(url_for('main.import_expenses_csv'))

        def parse_csv_date(value):
            value = (value or '').strip()
            for fmt in ('%Y-%m-%d', '%d-%m-%Y', '%m-%d-%Y'):
                try:
                    return datetime.strptime(value, fmt).date()
                except ValueError:
                    continue
            raise ValueError(f'Invalid date: {value}')

        try:
            stream = io.StringIO(file.stream.read().decode('utf-8-sig'), newline=None)
            reader = csv.DictReader(stream)

            def normalize_header(value):
                return (
                    (value or '')
                    .replace('\ufeff', '')
                    .strip()
                    .lower()
                    .replace('-', '_')
                    .replace(' ', '_')
                )

            alias_to_canonical = {
                'subcategory': 'sub_category',
                'sub_category': 'sub_category',
                'paymentdate': 'payment_date',
                'payment_date': 'payment_date',
                'invoicemonth': 'invoice_month',
                'invoice_month': 'invoice_month',
                'invoiceyear': 'invoice_year',
                'invoice_year': 'invoice_year',
                'cleantechentity': 'cleantech_entity',
                'cleantech_entity': 'cleantech_entity',
                'invoicedate': 'invoice_date',
                'invoice_date': 'invoice_date',
                'paymentmode': 'payment_mode',
                'payment_mode': 'payment_mode',
                'amountusd': 'amount_usd',
                'amount_usd': 'amount_usd',
            }

            raw_fieldnames = reader.fieldnames or []
            normalized_to_original = {}
            for field in raw_fieldnames:
                norm = normalize_header(field)
                canonical = alias_to_canonical.get(norm, norm)
                normalized_to_original[canonical] = field

            required_columns = {
                'category', 'sub_category', 'name', 'payment_date', 'invoice_month',
                'invoice_year', 'vendor', 'cleantech_entity', 'invoice_date', 'currency',
                'amount', 'payment_mode'
            }
            missing_columns = required_columns - set(normalized_to_original.keys())
            if missing_columns:
                flash(f'Missing required columns: {", ".join(sorted(missing_columns))}', 'danger')
                return redirect(url_for('main.import_expenses_csv'))

            allowed_map = {
                'hardware': {'laptop', 'monitor', 'tv', 'cable', 'remote', 'charger', 'connector'},
                'software': {'license'},
                'bills': {'wifi bills', 'others'},
                'others': {'others'},
            }

            imported_count = 0
            for idx, row in enumerate(reader, start=2):
                normalized_row = {}
                for k, v in row.items():
                    canonical = alias_to_canonical.get(normalize_header(k), normalize_header(k))
                    normalized_row[canonical] = v

                category = (normalized_row.get('category') or '').strip().lower()
                sub_category = (normalized_row.get('sub_category') or '').strip()
                vendor = (normalized_row.get('vendor') or '').strip()

                if category not in allowed_map:
                    raise ValueError(f'Row {idx}: invalid category "{category}"')
                if sub_category.lower() not in allowed_map[category]:
                    raise ValueError(f'Row {idx}: invalid sub_category "{sub_category}" for category "{category}"')
                if not ExpenseVendor.query.filter(db.func.lower(ExpenseVendor.name) == vendor.lower()).first():
                    raise ValueError(f'Row {idx}: vendor "{vendor}" is not pre-added')

                amount_val = normalized_row.get('amount')
                amount_usd_val = normalized_row.get('amount_usd')

                expense = Expense(
                    category=category,
                    sub_category=sub_category,
                    name=(normalized_row.get('name') or '').strip(),
                    payment_date=parse_csv_date(normalized_row.get('payment_date')),
                    invoice_month=int((normalized_row.get('invoice_month') or '').strip()),
                    invoice_year=int((normalized_row.get('invoice_year') or '').strip()),
                    vendor=vendor,
                    cleantech_entity=(normalized_row.get('cleantech_entity') or '').strip(),
                    invoice_date=parse_csv_date(normalized_row.get('invoice_date')),
                    currency=(normalized_row.get('currency') or '').strip(),
                    amount=Decimal(amount_val) if amount_val not in (None, '') else None,
                    amount_usd=Decimal(amount_usd_val) if amount_usd_val not in (None, '') else None,
                    payment_mode=(normalized_row.get('payment_mode') or '').strip(),
                    remarks=((normalized_row.get('remarks') or '').strip() or None),
                    created_by=current_user.username
                )

                if not all([
                    expense.category, expense.sub_category, expense.name, expense.payment_date,
                    expense.invoice_month, expense.invoice_year, expense.vendor, expense.cleantech_entity,
                    expense.invoice_date, expense.currency, expense.amount, expense.payment_mode
                ]):
                    raise ValueError(f'Row {idx}: required fields are missing')

                db.session.add(expense)
                imported_count += 1

            db.session.commit()
            log_user_activity('Expense CSV import', f'Imported {imported_count} expense rows')
            db.session.commit()
            flash(f'Expense CSV imported successfully. {imported_count} rows added.', 'success')
            return redirect(url_for('main.expenses'))
        except (ValueError, InvalidOperation) as e:
            db.session.rollback()
            current_app.logger.error(f'Error importing expense CSV: {e}')
            flash(f'CSV import failed: {e}', 'danger')
            return redirect(url_for('main.import_expenses_csv'))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f'Unexpected error importing expense CSV: {e}')
            flash('Unable to import expense CSV. Please check the file format.', 'danger')
            return redirect(url_for('main.import_expenses_csv'))

    return render_template('import_expenses_csv.html')


@main.route('/expenses/add', methods=['GET', 'POST'])
@login_required
def add_expense():
    blocked_response = block_read_only('add expenses')
    if blocked_response:
        return blocked_response

    if request.method == 'POST':
        try:
            category = request.form.get('category', '').strip().lower()
            sub_category = request.form.get('sub_category', '').strip()
            name = request.form.get('name', '').strip()
            payment_date = parse_iso_date(request.form.get('payment_date'))
            invoice_month = int(request.form.get('invoice_month', 0) or 0)
            invoice_year = int(request.form.get('invoice_year', 0) or 0)
            vendor = request.form.get('vendor', '').strip()
            cleantech_entity = request.form.get('cleantech_entity', '').strip()
            invoice_date = parse_iso_date(request.form.get('invoice_date'))
            currency = request.form.get('currency', '').strip()
            amount = Decimal(request.form.get('amount')) if request.form.get('amount') else None
            amount_usd = Decimal(request.form.get('amount_usd')) if request.form.get('amount_usd') else None
            payment_mode = request.form.get('payment_mode', '').strip()
            remarks = request.form.get('remarks', '').strip() or None

            allowed_map = {
                'hardware': {'laptop', 'monitor', 'tv', 'cable', 'remote', 'charger', 'connector'},
                'software': {'license'},
                'bills': {'wifi bills', 'others'},
                'others': {'others'},
            }

            if not all([category, sub_category, name, payment_date, invoice_month, invoice_year, vendor, cleantech_entity, invoice_date, currency, amount, payment_mode]):
                flash('All fields are required.', 'danger')
                return redirect(url_for('main.add_expense'))
            if not ExpenseVendor.query.filter(db.func.lower(ExpenseVendor.name) == vendor.lower()).first():
                flash('Please select a pre-added vendor, or add the vendor first.', 'danger')
                return redirect(url_for('main.add_expense'))
            if category not in allowed_map:
                flash('Invalid expense category.', 'danger')
                return redirect(url_for('main.add_expense'))
            if sub_category.lower() not in allowed_map[category]:
                flash('Invalid sub-category for selected category.', 'danger')
                return redirect(url_for('main.add_expense'))

            expense = Expense(
                category=category,
                sub_category=sub_category,
                name=name,
                payment_date=payment_date,
                invoice_month=invoice_month,
                invoice_year=invoice_year,
                vendor=vendor,
                cleantech_entity=cleantech_entity,
                invoice_date=invoice_date,
                currency=currency,
                amount=amount,
                amount_usd=amount_usd,
                payment_mode=payment_mode,
                remarks=remarks,
                created_by=current_user.username
            )
            db.session.add(expense)
            log_user_activity(
                'Expense created',
                f'category={category}, sub_category={sub_category}, name={name}, vendor={vendor}, amount={currency} {amount}, usd={amount_usd or "N/A"}, invoice={invoice_month}/{invoice_year}'
            )
            db.session.commit()
            flash('Expense posted successfully.', 'success')
            return redirect(url_for('main.expenses'))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f'Error adding expense: {e}')
            flash('Unable to add expense. Please verify your inputs.', 'danger')
            return redirect(url_for('main.add_expense'))

    vendors = ExpenseVendor.query.order_by(ExpenseVendor.name.asc()).all()
    return render_template('add_expense.html', vendors=vendors)


@main.route('/expenses/vendors', methods=['GET', 'POST'])
@login_required
def expense_vendors():
    if request.method == 'POST':
        blocked_response = block_read_only('add vendors')
        if blocked_response:
            return blocked_response

        name = request.form.get('name', '').strip()
        contact_person = request.form.get('contact_person', '').strip() or None
        email = request.form.get('email', '').strip() or None
        phone = request.form.get('phone', '').strip() or None
        remarks = request.form.get('remarks', '').strip() or None

        if not name:
            flash('Vendor name is required.', 'danger')
            return redirect(url_for('main.expense_vendors'))

        existing = ExpenseVendor.query.filter(db.func.lower(ExpenseVendor.name) == name.lower()).first()
        if existing:
            flash('Vendor already exists.', 'warning')
            return redirect(url_for('main.expense_vendors'))

        vendor = ExpenseVendor(
            name=name,
            contact_person=contact_person,
            email=email,
            phone=phone,
            remarks=remarks,
            created_by=current_user.username
        )
        db.session.add(vendor)
        log_user_activity('Expense vendor added', f'vendor={name}')
        db.session.commit()
        flash('Vendor added successfully.', 'success')
        return redirect(url_for('main.expense_vendors'))

    vendors = ExpenseVendor.query.order_by(ExpenseVendor.name.asc()).all()
    return render_template('expense_vendors.html', vendors=vendors)


@main.route('/expenses/vendors/delete/<int:vendor_id>', methods=['POST'])
@login_required
def delete_expense_vendor(vendor_id):
    blocked_response = block_read_only('delete vendors')
    if blocked_response:
        return blocked_response

    vendor = ExpenseVendor.query.get_or_404(vendor_id)

    used_count = Expense.query.filter(db.func.lower(Expense.vendor) == vendor.name.lower()).count()
    if used_count > 0:
        flash('Vendor is already used in expense entries and cannot be deleted.', 'danger')
        return redirect(url_for('main.expense_vendors'))

    log_user_activity('Expense vendor deleted', f'vendor={vendor.name}')
    db.session.delete(vendor)
    db.session.commit()
    flash('Vendor deleted successfully.', 'success')
    return redirect(url_for('main.expense_vendors'))


@main.route('/expenses/budget', methods=['POST'])
@login_required
def set_expense_budget():
    if not current_user.is_super_admin:
        flash('Only Admin can set yearly budgets.', 'danger')
        return redirect(url_for('main.expenses'))
        
    blocked_response = block_read_only('set yearly budgets')
    if blocked_response:
        return blocked_response

    try:
        year = int(request.form.get('year', 0) or 0)
        total_budget_usd = Decimal(request.form.get('total_budget_usd')) if request.form.get('total_budget_usd') else None

        if year < 2000 or total_budget_usd is None or total_budget_usd < 0:
            flash('Please provide valid year and budget amount.', 'danger')
            return redirect(url_for('main.expenses'))

        budget = ExpenseBudget.query.filter_by(year=year).first()
        if budget:
            old_budget = budget.total_budget_usd
            budget.total_budget_usd = total_budget_usd
            budget.updated_by = current_user.username
            budget.updated_at = datetime.utcnow()
            log_user_activity(
                'Expense budget updated',
                f'year={year}, old_budget_usd={old_budget}, new_budget_usd={total_budget_usd}'
            )
        else:
            budget = ExpenseBudget(
                year=year,
                total_budget_usd=total_budget_usd,
                created_by=current_user.username
            )
            db.session.add(budget)
            log_user_activity(
                'Expense budget created',
                f'year={year}, budget_usd={total_budget_usd}'
            )

        db.session.commit()
        flash('Yearly budget saved successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Error saving expense budget: {e}')
        flash('Unable to save yearly budget.', 'danger')

    return redirect(url_for('main.expenses'))


@main.route('/expenses/void/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def void_expense(expense_id):
    blocked_response = block_read_only('void expenses')
    if blocked_response:
        return blocked_response

    expense = Expense.query.get_or_404(expense_id)
    if request.method == 'POST':
        if expense.is_void:
            flash('Expense is already voided.', 'warning')
            return redirect(url_for('main.expenses'))

        remarks = request.form.get('void_remarks', '').strip()
        if not remarks:
            flash('Void remarks are required.', 'danger')
            return redirect(url_for('main.void_expense', expense_id=expense_id))

        expense.is_void = True
        expense.void_remarks = remarks
        expense.voided_by = current_user.username
        expense.voided_at = datetime.utcnow()
        log_user_activity(
            'Expense voided',
            f'id={expense.id}, name={expense.name}, remarks={remarks}'
        )
        db.session.commit()
        flash('Expense voided successfully.', 'success')
        return redirect(url_for('main.expenses'))

    return render_template('void_expense.html', expense=expense)

@main.context_processor
def inject_notification_count():
    from datetime import datetime, timedelta
    from app.models import Inventory

    today = datetime.today().date()
    warning_date = today + timedelta(days=30) # This is the "notify before" window

    expiring_assets_count = Inventory.query.filter(
        Inventory.warranty_end_date <= warning_date,
        Inventory.warranty_end_date >= today
    ).count()

    return dict(expiring_assets_count=expiring_assets_count)

@main.route('/repairs')
@login_required
def repairs():
    repairs_list = Repair.query.all()
    return render_template('repairs.html', repairs=repairs_list)

@main.route('/repairs/add', methods=['GET', 'POST'])
@login_required
def add_repair():
    blocked_response = block_read_only('add repairs')
    if blocked_response:
        return blocked_response

    form = RepairForm()
    if form.validate_on_submit():
        new_repair = Repair(
            asset_tag=form.asset_tag.data,
            serial_number=form.serial_number.data,
            brand=form.brand.data,
            model=form.model.data,
            part=form.part.data,
            issue_description=form.issue_description.data,
            repair_date=form.repair_date.data,
            registered_date=form.registered_date.data or datetime.utcnow().date(),
            repaired_under_warranty=form.repaired_under_warranty.data
        )

        db.session.add(new_repair)
        try:
            db.session.commit()
            flash('Repair record added successfully!', 'success')
            return redirect(url_for('main.repairs'))
        except IntegrityError:
            db.session.rollback()
            flash('A repair record for this laptop already exists!', 'warning')

    return render_template('add_repair.html', form=form)

@main.route('/repairs/edit/<int:repair_id>', methods=['GET', 'POST'])
@login_required
def edit_repair(repair_id):
    blocked_response = block_read_only('edit repairs')
    if blocked_response:
        return blocked_response

    repair = Repair.query.get_or_404(repair_id)
    form = RepairForm(obj=repair)  # Pre-fill with current values

    if form.validate_on_submit():
        repair.asset_tag = form.asset_tag.data
        repair.serial_number = form.serial_number.data
        repair.brand = form.brand.data
        repair.model = form.model.data
        repair.part = form.part.data
        repair.issue_description = form.issue_description.data
        repair.repair_date = form.repair_date.data
        repair.registered_date = form.registered_date.data
        repair.repaired_under_warranty = form.repaired_under_warranty.data

        try:
            db.session.commit()
            flash('Repair record updated successfully!', 'success')
            return redirect(url_for('main.repairs'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating record: {str(e)}', 'danger')

    return render_template('edit_repair.html', form=form, repair=repair)


@main.route('/repairs/delete/<int:repair_id>', methods=['POST'])
@login_required
def delete_repair(repair_id):
    blocked_response = block_read_only('delete repairs')
    if blocked_response:
        return blocked_response

    repair = Repair.query.get_or_404(repair_id)
    db.session.delete(repair)
    db.session.commit()
    flash('Repair record deleted!', 'success')
    return redirect(url_for('main.repairs'))

@main.route('/repairs/export', methods=['GET'])
@login_required
def export_repairs_csv():
    # Query all repair records
    repairs = Repair.query.all()

    # Create an in-memory file
    si = StringIO()
    writer = csv.writer(si)

    # Write CSV header
    writer.writerow([
        "ID", "Asset Tag", "Serial Number", "Brand", "Model",
        "Part", "Issue", "Repair Date", "Registered Date",
        "Repaired Under Warranty", "Created At"
    ])

    # Write rows
    for r in repairs:
        writer.writerow([
            r.id,
            r.asset_tag,
            r.serial_number,
            r.brand,
            r.model,
            r.part,
            r.issue_description,
            r.repair_date.strftime("%Y-%m-%d") if r.repair_date else "",
            r.registered_date.strftime("%Y-%m-%d") if r.registered_date else "",
            r.repaired_under_warranty or "",
            r.created_at.strftime("%Y-%m-%d %H:%M:%S") if r.created_at else ""
        ])

    # Prepare response
    output = Response(si.getvalue(), mimetype="text/csv")
    output.headers["Content-Disposition"] = "attachment; filename=repair_logs.csv"
    return output
