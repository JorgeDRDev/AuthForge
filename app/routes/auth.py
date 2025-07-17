"""
Authentication routes for user registration, login, logout, and token management.
Handles JWT token creation, refresh, and revocation.
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required, 
    get_jwt_identity, get_jwt, current_user
)
from marshmallow import Schema, fields, ValidationError, validates_schema
from marshmallow.validate import Length, Regexp
from datetime import datetime, timezone
from app import db, get_redis_client
from app.models.user import User, Role
from app.models.token_blacklist import TokenBlacklist, RedisTokenBlacklist

auth_bp = Blueprint('auth', __name__)


def get_json_or_error():
    """Helper to validate JSON requests."""
    if not request.is_json:
        return {
            'error': True,
            'response': jsonify({
                'message': 'Request must be JSON',
                'error': 'invalid_content_type'
            }), 
            'status': 400
        }

    json_data = request.get_json()
    if not json_data:
        return {
            'error': True,
            'response': jsonify({
                'message': 'Request body is empty',
                'error': 'empty_request'
            }), 
            'status': 400
        }

    return {'error': False, 'data': json_data}


class UserRegistrationSchema(Schema):
    """Schema for user registration validation."""
    email = fields.Email(required=True, validate=Length(max=255))
    password = fields.Str(required=True, validate=[
        Length(min=8, max=128),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]', 
               error='Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character')
    ])
    first_name = fields.Str(required=False, allow_none=True, validate=Length(max=100))
    last_name = fields.Str(required=False, allow_none=True, validate=Length(max=100))


class UserLoginSchema(Schema):
    """Schema for user login validation."""
    email = fields.Email(required=True, validate=Length(max=255))
    password = fields.Str(required=True, validate=Length(max=128))


class TokenRefreshSchema(Schema):
    """Schema for token refresh validation."""
    refresh_token = fields.Str(required=True)


class ChangePasswordSchema(Schema):
    """Schema for password change validation."""
    current_password = fields.Str(required=True, validate=Length(max=128))
    new_password = fields.Str(required=True, validate=[
        Length(min=8, max=128),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]', 
               error='Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character')
    ])


@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user account."""
    try:
        result = get_json_or_error()
        if result['error']:
            return result['response'], result['status']
        json_data = result['data']

        # Validate input data
        schema = UserRegistrationSchema()
        data = schema.load(json_data)
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user:
            return jsonify({
                'message': 'User with this email already exists',
                'error': 'user_exists'
            }), 400
        
        # Create new user
        user = User(
            email=data['email'],
            password=data['password'],
            first_name=data.get('first_name'),
            last_name=data.get('last_name')
        )
        
        # Assign default 'user' role
        user_role = Role.query.filter_by(name='user').first()
        if user_role:
            user.add_role(user_role)
        
        # Save user to database
        db.session.add(user)
        db.session.commit()
        
        # Create access and refresh tokens
        access_token = create_access_token(identity=user, fresh=True)
        refresh_token = create_refresh_token(identity=user)
        
        return jsonify({
            'message': 'User registered successfully',
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 201
        
    except ValidationError as e:
        return jsonify({
            'message': 'Validation error',
            'error': 'validation_error',
            'details': e.messages
        }), 400
    except ValueError as e:
        return jsonify({
            'message': str(e),
            'error': 'invalid_data'
        }), 400
    except Exception as e:
        current_app.logger.error(f"Registration error: {str(e)}")
        return jsonify({
            'message': 'Internal server error',
            'error': 'server_error'
        }), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    """Authenticate user and return JWT tokens."""
    try:
        result = get_json_or_error()
        if result['error']:
            return result['response'], result['status']
        json_data = result['data']

        # Validate input data
        schema = UserLoginSchema()
        data = schema.load(json_data)
        
        # Find user by email
        user = User.query.filter_by(email=data['email']).first()
        if not user:
            return jsonify({
                'message': 'User not registered',
                'error': 'invalid_credentials'
            }), 401
        
        # Check if account is locked
        if user.is_account_locked():
            return jsonify({
                'message': 'Account is temporarily locked due to failed login attempts',
                'error': 'account_locked'
            }), 423
        
        # Check if account is active
        if not user.is_active:
            return jsonify({
                'message': 'Account is deactivated',
                'error': 'account_inactive'
            }), 403
        
        # Verify password
        if not user.check_password(data['password']):
            # Increment failed attempts 
            user.increment_failed_attempts()
            db.session.commit()
            return jsonify({
                'message': 'Invalid email or password',
                'error': 'invalid_credentials'
            }), 401

        # Reset failed attempts on successful login
        user.reset_failed_attempts()
        db.session.commit()
        
        # Create access and refresh tokens
        access_token = create_access_token(identity=user, fresh=True)
        refresh_token = create_refresh_token(identity=user)
        
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 200

    except ValidationError as e:
        return jsonify({
            'message': 'Validation error',
            'error': 'validation_error',
            'details': e.messages
        }), 400
    except Exception as e:
        current_app.logger.error(f"Login error: {str(e)}")
        return jsonify({
            'message': 'Internal server error',
            'error': 'server_error'
        }), 500

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token using refresh token."""
    try:
        # Get current user from refresh token
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user or not user.is_active:
            return jsonify({
                'message': 'User not found or inactive',
                'error': 'user_not_found'
            }), 404
    
        # Create new access token (not fresh)
        access_token = create_access_token(identity=user, fresh=False)
        return jsonify({
            'message': 'Token refreshed successfully',
            'access_token': access_token
        }), 200
    except Exception as e:
        current_app.logger.error(f"Token refresh error: {str(e)}")
        return jsonify({
            'message': 'Internal server error',
            'error': 'server_error'
        }), 500

        
@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout user and revoke current token."""
    try:
        # Get current token info
        token = get_jwt()
        jti = token['jti']
        token_type = token['type']
        user_id = get_jwt_identity()
        expires_timestamp = token['exp']
        expires_at = datetime.fromtimestamp(expires_timestamp, tz=timezone.utc)
        # Blacklist the token
        redis_client = get_redis_client()
        if redis_client:
            blacklist = RedisTokenBlacklist(redis_client)
            blacklist.blacklist_token(jti, token_type, user_id, expires_at, "User logout")
        else:
            TokenBlacklist.blacklist_token(jti, token_type, user_id, expires_at, "User logout")
        
        return jsonify({
            'message': 'Logged out successfully'
        }), 200
    except Exception as e:
        current_app.logger.error(f"Logout error: {str(e)}")
        return jsonify({
            'message': 'Internal server error',
            'error': 'server_error'
        }), 500
        

@auth_bp.route('/logout-all', methods=['POST'])
@jwt_required()
def logout_all():
    """Logout user from all devices by revoking all tokens."""
    try:
        user_id = get_jwt_identity()
        # Revoke all user tokens
        redis_client = get_redis_client()
        if redis_client:
            blacklist = RedisTokenBlacklist(redis_client)
            revoked_count = blacklist.revoke_all_user_tokens(user_id, "Logout all devices")
        else:
            revoked_count = TokenBlacklist.revoke_all_user_tokens(user_id, "Logout all devices")
        
        return jsonify({
            'message': 'Logged out from all devices successfully',
            'revoked_tokens': revoked_count
        }), 200
    except Exception as e:
        current_app.logger.error(f"Logout all error: {str(e)}")
        return jsonify({
            'message': 'Internal server error',
            'error': 'server_error'
        }), 500
        

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user information."""
    try:
        return jsonify({
            'user': current_user.to_dict()
        }), 200
    except Exception as e:
        current_app.logger.error(f"Get current user error: {str(e)}")
        return jsonify({
            'message': 'Internal server error',
            'error': 'server_error'
        }), 500
        

@auth_bp.route('/verify-token', methods=['POST'])
@jwt_required()
def verify_token():
    """Verify if the provided token is valid."""
    try:
        token = get_jwt()
        return jsonify({
            'message': 'Token is valid',
            'token_info': {
                'jti': token['jti'],
                'type': token['type'],
                'fresh': token['fresh'],
                'exp': token['exp'],
                'iat': token['iat']
            },
            'user': current_user.to_dict()
        }), 200
    except Exception as e:
        current_app.logger.error(f"Token verification error: {str(e)}")
        return jsonify({
            'message': 'Internal server error',
            'error': 'server_error'
        }), 500
            
        
@auth_bp.route('/change-password', methods=['POST'])
@jwt_required(fresh=True)
def change_password():
    """Change user password (requires fresh token)."""
    try:
        result = get_json_or_error()
        if result['error']:
            return result['response'], result['status']
        json_data = result['data']
        
        # Validate input data
        schema = ChangePasswordSchema()
        data = schema.load(json_data)
        
        current_password = data['current_password']
        new_password = data['new_password']
        # Verify current password
        if not current_user.check_password(current_password):
            return jsonify({
                'message': 'Current password is incorrect',
                'error': 'invalid_password'
            }), 401
        # Update password
        current_user.set_password(new_password)
        db.session.commit()
        return jsonify({
            'message': 'Password changed successfully'
        }), 200
        
    except ValidationError as e:
        return jsonify({
            'message': 'Validation error',
            'error': 'validation_error',
            'details': e.messages
        }), 400
    except ValueError as e:
        return jsonify({
            'message': str(e),
            'error': 'invalid_data'
        }), 400
    except Exception as e:
        current_app.logger.error(f"Change password error: {str(e)}")
        return jsonify({
            'message': 'Internal server error',
            'error': 'server_error'
        }), 500
