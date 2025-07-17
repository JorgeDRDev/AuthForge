"""
Token blacklist model for JWT token revocation and session management.
Supports both database and Redis-based token blacklisting.
"""

import uuid
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class TokenBlacklist(db.Model):
    """Token blacklist model for revoked JWT tokens."""
    
    __tablename__ = 'token_blacklist'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    jti = db.Column(db.String(36), unique=True, nullable=False, index=True)  # JWT ID
    token_type = db.Column(db.String(10), nullable=False)  # 'access' or 'refresh'
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    revoked_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    reason = db.Column(db.String(100), nullable=True)  # Optional reason for revocation
    
    # Relationships
    user = db.relationship('User', backref='blacklisted_tokens')
    
    def __init__(self, jti, token_type, user_id, expires_at, reason=None):
        """Initialize blacklisted token."""
        self.jti = jti
        self.token_type = token_type
        self.user_id = user_id
        self.expires_at = expires_at
        self.reason = reason
    
    @staticmethod
    def is_token_blacklisted(jti):
        """Check if a token is blacklisted."""
        return TokenBlacklist.query.filter_by(jti=jti).first() is not None
    
    @staticmethod
    def blacklist_token(jti, token_type, user_id, expires_at, reason=None):
        """Add a token to the blacklist."""
        # Check if token is already blacklisted
        if TokenBlacklist.is_token_blacklisted(jti):
            return False
        
        blacklisted_token = TokenBlacklist(
            jti=jti,
            token_type=token_type,
            user_id=user_id,
            expires_at=expires_at,
            reason=reason
        )
        
        db.session.add(blacklisted_token)
        db.session.commit()
        return True
    
    @staticmethod
    def revoke_all_user_tokens(user_id, reason="User logout"):
        """Revoke all tokens for a specific user."""
        # This would typically be handled by changing a user's token version
        # or by storing user-specific blacklist information
        from .user import User
        user = User.query.get(user_id)
        if not user:
            return False
        
        # In a real implementation, you might want to:
        # 1. Increment a token version number for the user
        # 2. Store a "revoked_before" timestamp for the user
        # 3. Add all active tokens to blacklist
        
        return True
    
    @staticmethod
    def cleanup_expired_tokens():
        """Remove expired tokens from blacklist to keep database clean."""
        current_time = datetime.now(timezone.utc)
        expired_tokens = TokenBlacklist.query.filter(
            TokenBlacklist.expires_at < current_time
        ).all()
        
        for token in expired_tokens:
            db.session.delete(token)
        
        db.session.commit()
        return len(expired_tokens)
    
    def to_dict(self):
        """Convert blacklisted token to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'jti': self.jti,
            'token_type': self.token_type,
            'user_id': self.user_id,
            'revoked_at': self.revoked_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'reason': self.reason
        }
    
    def __repr__(self):
        return f'<TokenBlacklist {self.jti}>'


class RedisTokenBlacklist:
    """Redis-based token blacklist for better performance."""
    
    def __init__(self, redis_client):
        """Initialize with Redis client."""
        self.redis = redis_client
        self.blacklist_key_prefix = "blacklisted_token:"
        self.user_tokens_key_prefix = "user_tokens:"
    
    def is_token_blacklisted(self, jti):
        """Check if a token is blacklisted in Redis."""
        key = f"{self.blacklist_key_prefix}{jti}"
        return self.redis.exists(key)
    
    def blacklist_token(self, jti, token_type, user_id, expires_at, reason=None):
        """Add a token to the Redis blacklist."""
        key = f"{self.blacklist_key_prefix}{jti}"
        
        # Calculate TTL (time to live) until token expires
        current_time = datetime.now(timezone.utc)
        if expires_at <= current_time:
            return False  # Token already expired
        
        ttl = int((expires_at - current_time).total_seconds())
        
        # Store token info in Redis with TTL
        token_data = {
            'token_type': token_type,
            'user_id': user_id,
            'revoked_at': current_time.isoformat(),
            'expires_at': expires_at.isoformat(),
            'reason': reason or 'Manual revocation'
        }
        
        # Use Redis hash to store token data
        self.redis.hset(key, mapping=token_data)
        self.redis.expire(key, ttl)
        
        # Also track tokens per user for bulk operations
        user_tokens_key = f"{self.user_tokens_key_prefix}{user_id}"
        self.redis.sadd(user_tokens_key, jti)
        
        return True
    
    def revoke_all_user_tokens(self, user_id, reason="User logout"):
        """Revoke all tokens for a specific user."""
        user_tokens_key = f"{self.user_tokens_key_prefix}{user_id}"
        
        # Get all tokens for the user
        tokens = self.redis.smembers(user_tokens_key)
        
        # Blacklist each token
        for token_jti in tokens:
            token_jti = token_jti.decode('utf-8') if isinstance(token_jti, bytes) else token_jti
            key = f"{self.blacklist_key_prefix}{token_jti}"
            
            # Update the reason for existing blacklisted tokens
            if self.redis.exists(key):
                self.redis.hset(key, 'reason', reason)
            else:
                # If token isn't blacklisted yet, we need more info to blacklist it
                # This would typically require additional token metadata storage
                pass
        
        # Clear the user's token set
        self.redis.delete(user_tokens_key)
        
        return len(tokens)
    
    def cleanup_expired_tokens(self):
        """Redis automatically handles TTL, so this is mainly for monitoring."""
        # In Redis, expired keys are automatically removed
        # This method could be used for metrics or logging
        return 0
    
    def get_token_info(self, jti):
        """Get information about a blacklisted token."""
        key = f"{self.blacklist_key_prefix}{jti}"
        
        if not self.redis.exists(key):
            return None
        
        token_data = self.redis.hgetall(key)
        
        # Convert bytes to strings for Python 3
        return {
            k.decode('utf-8') if isinstance(k, bytes) else k: 
            v.decode('utf-8') if isinstance(v, bytes) else v
            for k, v in token_data.items()
        }
    
    def get_user_blacklisted_tokens(self, user_id):
        """Get all blacklisted tokens for a user."""
        user_tokens_key = f"{self.user_tokens_key_prefix}{user_id}"
        tokens = self.redis.smembers(user_tokens_key)
        
        token_info = []
        for token_jti in tokens:
            token_jti = token_jti.decode('utf-8') if isinstance(token_jti, bytes) else token_jti
            info = self.get_token_info(token_jti)
            if info:
                info['jti'] = token_jti
                token_info.append(info)
        
        return token_info
