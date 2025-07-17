"""
Flask application factory for AuthForge.
Initializes database, JWT, Redis, and configures all extensions.
"""

import os
import redis
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from config.config import get_config

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
redis_client = None


def create_app(config_name=None):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Load configuration
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'development')
    
    config_class = get_config()
    app.config.from_object(config_class)
    
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    
    # Initialize Redis for token blacklisting
    global redis_client
    try:
        redis_client = redis.from_url(app.config['REDIS_URL'])
        # Test Redis connection
        redis_client.ping()
        app.logger.info("Redis connected successfully")
    except Exception as e:
        app.logger.warning(f"Redis connection failed: {e}")
        redis_client = None
    
    # Configure CORS
    CORS(app, origins=app.config['CORS_ORIGINS'])
    
    # Configure JWT
    configure_jwt(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Create database tables
    with app.app_context():
        db.create_all()
        
        # Create default roles
        from app.models.user import Role
        Role.create_default_roles()
    
    return app


def configure_jwt(app):
    """Configure JWT settings and token blacklist checking."""
    from app.models.token_blacklist import TokenBlacklist, RedisTokenBlacklist
    
    # Initialize blacklist handler
    if redis_client:
        blacklist = RedisTokenBlacklist(redis_client)
    else:
        blacklist = None
    
    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        """Check if a token has been revoked."""
        jti = jwt_payload['jti']
        
        # Try Redis first if available
        if blacklist:
            return blacklist.is_token_blacklisted(jti)
        
        # Fallback to database
        return TokenBlacklist.is_token_blacklisted(jti)
    
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        """Handle expired tokens."""
        return {
            'message': 'The token has expired',
            'error': 'token_expired'
        }, 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        """Handle invalid tokens."""
        return {
            'message': 'Invalid token',
            'error': 'invalid_token'
        }, 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        """Handle missing tokens."""
        return {
            'message': 'Authorization token is required',
            'error': 'authorization_required'
        }, 401
    
    @jwt.needs_fresh_token_loader
    def token_not_fresh_callback(jwt_header, jwt_payload):
        """Handle non-fresh tokens when fresh token is required."""
        return {
            'message': 'Fresh token required',
            'error': 'fresh_token_required'
        }, 401
    
    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        """Handle revoked tokens."""
        return {
            'message': 'The token has been revoked',
            'error': 'token_revoked'
        }, 401
    
    @jwt.user_identity_loader
    def user_identity_lookup(user):
        """Define what to use as the identity in JWT tokens."""
        return user.id
    
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        """Load user from JWT token."""
        from app.models.user import User
        identity = jwt_data["sub"]
        return User.query.get(identity)


def register_blueprints(app):
    """Register all application blueprints."""
    from app.routes.auth import auth_bp
    from app.routes.users import users_bp
    from app.routes.admin import admin_bp
    
    # Register blueprints with URL prefixes
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(users_bp, url_prefix='/api/users')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    
    # Health check endpoint
    @app.route('/health')
    def health_check():
        """Health check endpoint."""
        return {
            'status': 'healthy',
            'message': 'AuthForge API is running',
            'redis_connected': redis_client is not None
        }
    
    @app.route('/')
    def index():
        """Root endpoint."""
        return {
            'message': 'Welcome to AuthForge API',
            'version': '1.0.0',
            'endpoints': {
                'auth': '/api/auth',
                'users': '/api/users',
                'admin': '/api/admin',
                'health': '/health'
            }
        }


def get_redis_client():
    """Get the Redis client instance."""
    return redis_client
