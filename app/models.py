from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from sqlalchemy import ForeignKey

# User Model
class User(db.Model, UserMixin):
    ROLE_NORMAL_USER = 'normal_user'
    ROLE_READ_ONLY = 'read_only'
    ROLE_FULL_CONTROL = 'full_control'
    ROLE_FULL_CONTROL_NO_DELETE = 'full_control_no_delete'
    ROLE_FULL_CONTROL_NO_DELETE_NO_ADD_USER = 'full_control_no_delete_no_add_user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    # Werkzeug scrypt hashes are longer than 128 chars.
    password_hash = db.Column(db.String(255))
    role = db.Column(db.String(64), nullable=False, default=ROLE_NORMAL_USER)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_super_admin(self):
        return self.username == 'Admin'

    @property
    def is_read_only(self):
        return self.role == self.ROLE_READ_ONLY

    @property
    def is_elevated(self):
        return self.role in {
            self.ROLE_FULL_CONTROL,
            self.ROLE_FULL_CONTROL_NO_DELETE,
            self.ROLE_FULL_CONTROL_NO_DELETE_NO_ADD_USER,
        } or self.is_super_admin

    @property
    def can_manage_users(self):
        return self.is_elevated

    @property
    def can_add_users(self):
        return self.role in {self.ROLE_FULL_CONTROL, self.ROLE_FULL_CONTROL_NO_DELETE} or self.is_super_admin

    @property
    def can_delete_users(self):
        return self.role == self.ROLE_FULL_CONTROL or self.is_super_admin

    @property
    def can_delete_items(self):
        return self.role == self.ROLE_FULL_CONTROL or self.is_super_admin

    @property
    def can_assign_assets(self):
        return self.is_elevated

    @property
    def can_add_items(self):
        return not self.is_read_only

    @property
    def can_edit_items(self):
        return not self.is_read_only

    @property
    def can_import_items(self):
        return self.is_elevated and not self.is_read_only

    @property
    def can_manage_repairs(self):
        return not self.is_read_only

    @property
    def can_manage_licenses(self):
        return not self.is_read_only

    @property
    def can_manage_expenses(self):
        return not self.is_read_only

    @property
    def access_label(self):
        labels = {
            self.ROLE_NORMAL_USER: 'Normal User',
            self.ROLE_READ_ONLY: 'Read Only (View Only)',
            self.ROLE_FULL_CONTROL: 'Full Control',
            self.ROLE_FULL_CONTROL_NO_DELETE: 'Full Control (No Delete Item/User)',
            self.ROLE_FULL_CONTROL_NO_DELETE_NO_ADD_USER: 'Full Control (No Delete + No Add User)',
        }
        return labels.get(self.role, 'Normal User')


class PreUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False, index=True)
    department = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

# Inventory Model
class Inventory(db.Model):
    __tablename__ = 'inventory'

    id = db.Column(db.Integer, primary_key=True)
    asset_tag = db.Column(db.String(100), nullable=False, unique=True, index=True)
    asset_type = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(100), nullable=False)
    brand = db.Column(db.String(100), nullable=False)
    model = db.Column(db.String(100), nullable=False)
    fa_code = db.Column(db.String(100), nullable=False)
    serial_number = db.Column(db.String(100), nullable=False, unique=True)
    operating_system = db.Column(db.String(100), nullable=False)
    purchase_date = db.Column(db.Date, nullable=False)
    purchase_amount = db.Column(db.Numeric(10, 2))
    age = db.Column(db.Integer, nullable=False)
    current_owner = db.Column(db.String(100), nullable=False)
    previous_owner = db.Column(db.String(100))
    warranty_end_date = db.Column(db.Date)
    condition_notes = db.Column(db.Text)
    department = db.Column(db.String(100))
    office = db.Column(db.String(100))
    country = db.Column(db.String(100))
    vendor_location = db.Column(db.String(100))
    updated_by = db.Column(db.String(100), nullable=True)
    is_deleted = db.Column(db.Boolean, default=False)  # Must exist
    deleted_at = db.Column(db.DateTime, nullable=True)
    deleted_by = db.Column(db.String(50), nullable=True)

    # Deletion tracking
    is_deleted = db.Column(db.Boolean, default=False)
    deleted_at = db.Column(db.DateTime)
    deleted_by = db.Column(db.String(100))

    # Relationship with Log model
    logs = db.relationship('Log', backref='related_inventory', lazy=True, overlaps="log_entries,inventory")

# Log Model
class Log(db.Model):
    __tablename__ = 'log'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='logs')
    action = db.Column(db.String(255), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('inventory.id', ondelete='SET NULL'), nullable=True)
    changes = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    serial_number = db.Column(db.String(100), nullable=True)  # Matches Inventory serial_number for tracking

    # Relationship with Inventory for tracking history
    inventory = db.relationship('Inventory', backref='log_entries', foreign_keys=[item_id], overlaps="logs,related_inventory")

# License Model
class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    purchase_date = db.Column(db.Date, nullable=True)
    expiry_date = db.Column(db.Date, nullable=True)
    amount_per_unit = db.Column(db.Numeric(10, 2), nullable=True)
    total_license = db.Column(db.Integer, nullable=True)
    remaining_license = db.Column(db.Integer, nullable=True)
    last_renewal_date = db.Column(db.Date, nullable=True)

    # Relationship with LicenseDetails
    details = db.relationship('LicenseDetails', backref='license', cascade='all, delete-orphan')
    renewals = db.relationship('LicenseRenewal', backref='license', cascade='all, delete-orphan')

# LicenseDetails Model
class LicenseDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    license_id = db.Column(db.Integer, db.ForeignKey('license.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    current_owner = db.Column(db.String(100), nullable=False)
    purchase_date = db.Column(db.Date, nullable=False)
    expiry_date = db.Column(db.Date, nullable=False)
    remarks = db.Column(db.String(255), nullable=True)


class LicenseRenewal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    license_id = db.Column(db.Integer, db.ForeignKey('license.id'), nullable=False, index=True)
    renewal_date = db.Column(db.Date, nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=True)
    remarks = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False, unique=True, index=True)
    purchase_date = db.Column(db.Date, nullable=False)
    renewal_date = db.Column(db.Date, nullable=False)
    country = db.Column(db.String(100), nullable=True)
    amount = db.Column(db.Numeric(10, 2), nullable=True)
    last_renewal_date = db.Column(db.Date, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    renewals = db.relationship('DomainRenewal', backref='domain_ref', cascade='all, delete-orphan')


class DomainRenewal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=False, index=True)
    renewal_date = db.Column(db.Date, nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=True)
    remarks = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), nullable=False, index=True)
    sub_category = db.Column(db.String(100), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    payment_date = db.Column(db.Date, nullable=False, index=True)
    invoice_month = db.Column(db.Integer, nullable=False)
    invoice_year = db.Column(db.Integer, nullable=False, index=True)
    vendor = db.Column(db.String(255), nullable=False, index=True)
    cleantech_entity = db.Column(db.String(255), nullable=False, index=True)
    invoice_date = db.Column(db.Date, nullable=False)
    currency = db.Column(db.String(10), nullable=False)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    amount_usd = db.Column(db.Numeric(12, 2), nullable=True)
    payment_mode = db.Column(db.String(50), nullable=False)
    remarks = db.Column(db.Text, nullable=True)
    created_by = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_void = db.Column(db.Boolean, default=False, nullable=False)
    void_remarks = db.Column(db.Text, nullable=True)
    voided_by = db.Column(db.String(150), nullable=True)
    voided_at = db.Column(db.DateTime, nullable=True)


class ExpenseVendor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False, index=True)
    contact_person = db.Column(db.String(150), nullable=True)
    email = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    remarks = db.Column(db.String(255), nullable=True)
    created_by = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class ExpenseBudget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    year = db.Column(db.Integer, unique=True, nullable=False, index=True)
    total_budget_usd = db.Column(db.Numeric(14, 2), nullable=False)
    created_by = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_by = db.Column(db.String(150), nullable=True)
    updated_at = db.Column(db.DateTime, nullable=True)


class Repair(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_tag = db.Column(db.String(100), nullable=False, unique=True, index=True)
    serial_number = db.Column(db.String(100), nullable=False, unique=True)
    brand = db.Column(db.String(100), nullable=False)
    model = db.Column(db.String(100), nullable=False)
    part = db.Column(db.String(100), nullable=False)
    issue_description = db.Column(db.Text, nullable=True)
    repair_date = db.Column(db.Date)
    registered_date = db.Column(db.Date, default=datetime.utcnow)
    repaired_under_warranty = db.Column(db.String(10))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class RepairHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    inventory_id = db.Column(db.Integer, db.ForeignKey('inventory.id'), nullable=False, index=True)
    asset_tag = db.Column(db.String(100), nullable=False)
    serial_number = db.Column(db.String(100), nullable=False)
    part = db.Column(db.String(100), nullable=False)
    issue_description = db.Column(db.Text, nullable=True)
    repair_date = db.Column(db.Date, nullable=False)
    registered_date = db.Column(db.Date, default=datetime.utcnow)
    repaired_under_warranty = db.Column(db.String(10), nullable=True)
    remarks = db.Column(db.String(255), nullable=True)
    created_by = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    inventory = db.relationship('Inventory', backref='repair_history_entries')
