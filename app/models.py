from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from sqlalchemy import ForeignKey

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

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
    depreciated_value = db.Column(db.Numeric(10, 2))
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

    # Relationship with LicenseDetails
    details = db.relationship('LicenseDetails', backref='license', cascade='all, delete-orphan')

# LicenseDetails Model
class LicenseDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    license_id = db.Column(db.Integer, db.ForeignKey('license.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    current_owner = db.Column(db.String(100), nullable=False)
    purchase_date = db.Column(db.Date, nullable=False)
    expiry_date = db.Column(db.Date, nullable=False)
    remarks = db.Column(db.String(255), nullable=True)


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