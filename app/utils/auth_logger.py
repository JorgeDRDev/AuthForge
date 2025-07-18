"""
Authentication event logging utility for security monitoring.
Logs critical authentication events to file for security analysis.
"""

import logging
import os
from datetime import datetime, timezone
from flask import request, current_app
from functools import wraps


class AuthLogger:
    """Logger for authentication events and security monitoring."""
    
    def __init__(self, log_file=None):
        """Initialize the authentication logger."""
        self.log_file = log_file or os.path.join(os.getcwd(), 'logs', 'auth.log')
        self.logger = self._setup_logger()
    
    def _setup_logger(self):
        """Setup the authentication logger with file handler."""
        logger = logging.getLogger('authforge.auth')
        logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        
        # Create file handler
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        
        # Add handler to logger if not already added
        if not logger.handlers:
            logger.addHandler(file_handler)
        
        return logger
    
    def _get_client_info(self):
        """Get client information for logging."""
        return {
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'endpoint': request.endpoint,
            'method': request.method,
            'path': request.path
        }
    
    def log_event(self, event_type, user_id=None, email=None, details=None, level='INFO'):
        """Log an authentication event."""
        try:
            client_info = self._get_client_info()
            
            log_entry = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'event_type': event_type,
                'user_id': user_id,
                'email': email,
                'client_ip': client_info['ip'],
                'user_agent': client_info['user_agent'],
                'endpoint': client_info['endpoint'],
                'method': client_info['method'],
                'path': client_info['path'],
                'details': details or {}
            }
            
            # Format log message
            message = f"EVENT: {event_type}"
            if user_id:
                message += f" | USER_ID: {user_id}"
            if email:
                message += f" | EMAIL: {email}"
            message += f" | IP: {client_info['ip']}"
            message += f" | ENDPOINT: {client_info['endpoint']}"
            if details:
                message += f" | DETAILS: {details}"
            
            # Log based on level
            if level == 'WARNING':
                self.logger.warning(message)
            elif level == 'ERROR':
                self.logger.error(message)
            elif level == 'CRITICAL':
                self.logger.critical(message)
            else:
                self.logger.info(message)
                
        except Exception as e:
            # Fallback logging if main logger fails
            current_app.logger.error(f"Auth logger failed: {str(e)}")
    
    def log_successful_login(self, user_id, email):
        """Log successful login attempt."""
        self.log_event('LOGIN_SUCCESS', user_id=user_id, email=email)
    
    def log_failed_login(self, email, reason=None):
        """Log failed login attempt."""
        details = {'reason': reason} if reason else None
        self.log_event('LOGIN_FAILED', email=email, details=details, level='WARNING')
    
    def log_registration(self, user_id, email):
        """Log successful user registration."""
        self.log_event('REGISTRATION_SUCCESS', user_id=user_id, email=email)
    
    def log_password_change(self, user_id, email):
        """Log password change."""
        self.log_event('PASSWORD_CHANGE', user_id=user_id, email=email)
    
    def log_token_refresh(self, user_id, email):
        """Log token refresh."""
        self.log_event('TOKEN_REFRESH', user_id=user_id, email=email)
    
    def log_logout(self, user_id, email, logout_type='single'):
        """Log logout event."""
        details = {'logout_type': logout_type}
        self.log_event('LOGOUT', user_id=user_id, email=email, details=details)
    
    def log_account_lockout(self, user_id, email, failed_attempts):
        """Log account lockout due to failed attempts."""
        details = {'failed_attempts': failed_attempts}
        self.log_event('ACCOUNT_LOCKOUT', user_id=user_id, email=email, details=details, level='WARNING')
    
    def log_suspicious_activity(self, user_id=None, email=None, activity_type=None, details=None):
        """Log suspicious activity."""
        event_details = {'activity_type': activity_type}
        if details:
            event_details.update(details)
        self.log_event('SUSPICIOUS_ACTIVITY', user_id=user_id, email=email, 
                      details=event_details, level='CRITICAL')


# Global auth logger instance
auth_logger = AuthLogger()


def log_auth_event(event_type, level='INFO'):
    """Decorator to log authentication events."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
                
                # Log based on function result if it's a tuple (response, status)
                if isinstance(result, tuple) and len(result) >= 2:
                    response_data, status_code = result[0], result[1]
                    
                    # Extract user info from response if available
                    user_id = None
                    email = None
                    
                    if hasattr(response_data, 'get_json'):
                        json_data = response_data.get_json()
                        if json_data and 'user' in json_data:
                            user_id = json_data['user'].get('id')
                            email = json_data['user'].get('email')
                    
                    # Log success or failure based on status code
                    if 200 <= status_code < 300:
                        auth_logger.log_event(f"{event_type}_SUCCESS", user_id=user_id, email=email)
                    else:
                        auth_logger.log_event(f"{event_type}_FAILED", user_id=user_id, email=email, level='WARNING')
                
                return result
                
            except Exception as e:
                auth_logger.log_event(f"{event_type}_ERROR", details={'error': str(e)}, level='ERROR')
                raise
        
        return wrapper
    return decorator
