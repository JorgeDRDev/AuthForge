"""
User model with authentication and role management.
Uses Argon2 for secure password hashing and supports role-based access control.
"""

import uuid
from datetime import datetime, timezone, timedelta
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask_sqlalchemy import SQLAlchemy
from email_validator import validate_email, EmailNotValidError

db = SQLAlchemy()


class User(db.Model):
    """User model with secure password hashing and role management."""
    
    __tablename__ = 'users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(100), nullable=True)
    last_name = db.Column(db.String(100), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), 
                          onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    roles = db.relationship('UserRole', back_populates='user', cascade='all, delete-orphan')
    
    def __init__(self, email, password, first_name=None, last_name=None):
        """Initialize user with email and password."""
        self.email = self._validate_email(email)
        self.set_password(password)
        self.first_name = first_name
        self.last_name = last_name
    
    @staticmethod
    def _validate_email(email):
        """Validate email format."""
        try:
            # Validate and get normalized result
            valid = validate_email(email)
            return valid.email
        except EmailNotValidError:
            raise ValueError("Invalid email format")
    
    def set_password(self, password):
        """Hash and set password using Argon2."""
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        ph = PasswordHasher()
        self.password_hash = ph.hash(password)
    
    def check_password(self, password):
        """Verify password against stored hash."""
        if not password:
            return False
        
        ph = PasswordHasher()
        try:
            ph.verify(self.password_hash, password)
            return True
        except VerifyMismatchError:
            return False
    
    def is_account_locked(self):
        """Check if account is locked due to failed login attempts."""
        if self.locked_until and datetime.now(timezone.utc) < self.locked_until:
            return True
        return False
    
    def increment_failed_attempts(self):
        """Increment failed login attempts and lock account if necessary."""
        self.failed_login_attempts += 1
        
        # Lock account after 5 failed attempts for 30 minutes
        if self.failed_login_attempts >= 5:
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
    
    def reset_failed_attempts(self):
        """Reset failed login attempts after successful login."""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login = datetime.now(timezone.utc)
    
    def has_role(self, role_name):
        """Check if user has a specific role."""
        return any(user_role.role.name == role_name for user_role in self.roles)
    
    def add_role(self, role):
        """Add a role to the user."""
        if not self.has_role(role.name):
            user_role = UserRole(user_id=self.id, role_id=role.id)
            self.roles.append(user_role)
    
    def remove_role(self, role_name):
        """Remove a role from the user."""
        user_role = next((ur for ur in self.roles if ur.role.name == role_name), None)
        if user_role:
            self.roles.remove(user_role)
    
    def get_roles(self):
        """Get list of role names for the user."""
        return [user_role.role.name for user_role in self.roles]
    
    def to_dict(self, include_sensitive=False):
        """Convert user to dictionary for JSON serialization."""
        data = {
            'id': self.id,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'roles': self.get_roles()
        }
        
        if include_sensitive:
            data.update({
                'failed_login_attempts': self.failed_login_attempts,
                'locked_until': self.locked_until.isoformat() if self.locked_until else None
            })
        
        return data
    
    def __repr__(self):
        return f'<User {self.email}>'


class Role(db.Model):
    """Role model for role-based access control."""
    
    __tablename__ = 'roles'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationships
    users = db.relationship('UserRole', back_populates='role', cascade='all, delete-orphan')
    
    def __init__(self, name, description=None):
        """Initialize role with name and optional description."""
        self.name = name
        self.description = description
    
    def to_dict(self):
        """Convert role to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at.isoformat()
        }
    
    @staticmethod
    def create_default_roles():
        """Create default roles if they don't exist."""
        default_roles = [
            ('admin', 'Administrator with full access'),
            ('user', 'Standard user with basic access'),
            ('moderator', 'Moderator with limited admin access')
        ]
        
        for role_name, description in default_roles:
            existing_role = Role.query.filter_by(name=role_name).first()
            if not existing_role:
                role = Role(name=role_name, description=description)
                db.session.add(role)
        
        db.session.commit()
    
    def __repr__(self):
        return f'<Role {self.name}>'


class UserRole(db.Model):
    """Association table for many-to-many relationship between users and roles."""
    
    __tablename__ = 'user_roles'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    role_id = db.Column(db.String(36), db.ForeignKey('roles.id'), nullable=False)
    assigned_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationships
    user = db.relationship('User', back_populates='roles')
    role = db.relationship('Role', back_populates='users')
    
    # Ensure unique user-role combinations
    __table_args__ = (db.UniqueConstraint('user_id', 'role_id', name='_user_role_uc'),)
    
    def __repr__(self):
        return f'<UserRole {self.user_id}-{self.role_id}>'
