"""
Security tests for AuthForge API's authentication endpoints.
Tests include rate limiting, input validation, and security measures.
"""

import pytest
import time
from flask import url_for
from app import create_app, db
from app.models.user import User


@pytest.fixture(scope='module')
def test_client():
    """Create test client for the application."""
    flask_app = create_app('testing')

    # Create a context for the app
    with flask_app.app_context():
        # Create all db tables
        db.create_all()

    # Setup a test client (no context)
    with flask_app.test_client() as testing_client:
        # Establish application context
        with flask_app.app_context():
            yield testing_client

    # Remove the test database
    with flask_app.app_context():
        db.drop_all()


def test_registration_validation(test_client):
    """Test registration input validation."""
    client = test_client
    
    # Test missing email
    response = client.post(
        url_for('auth.register'),
        json={
            'password': 'Password123!',
            'first_name': 'Test',
            'last_name': 'User'
        }
    )
    assert response.status_code == 400
    data = response.get_json()
    assert 'validation_error' in data['error']
    
    # Test invalid email format
    response = client.post(
        url_for('auth.register'),
        json={
            'email': 'invalid-email',
            'password': 'Password123!',
            'first_name': 'Test',
            'last_name': 'User'
        }
    )
    assert response.status_code == 400
    
    # Test weak password
    response = client.post(
        url_for('auth.register'),
        json={
            'email': 'test@example.com',
            'password': 'weak',
            'first_name': 'Test',
            'last_name': 'User'
        }
    )
    assert response.status_code == 400


def test_login_validation(test_client):
    """Test login input validation."""
    client = test_client
    
    # First register a user
    client.post(
        url_for('auth.register'),
        json={
            'email': 'test@example.com',
            'password': 'Password123!',
            'first_name': 'Test',
            'last_name': 'User'
        }
    )
    
    # Test missing email
    response = client.post(
        url_for('auth.login'),
        json={
            'password': 'Password123!'
        }
    )
    assert response.status_code == 400
    
    # Test invalid credentials
    response = client.post(
        url_for('auth.login'),
        json={
            'email': 'test@example.com',
            'password': 'wrongpassword'
        }
    )
    assert response.status_code == 401
    
    # Test non-existent user
    response = client.post(
        url_for('auth.login'),
        json={
            'email': 'nonexistent@example.com',
            'password': 'Password123!'
        }
    )
    assert response.status_code == 401


def test_duplicate_registration(test_client):
    """Test duplicate user registration."""
    client = test_client
    
    # Register a user
    response = client.post(
        url_for('auth.register'),
        json={
            'email': 'duplicate@example.com',
            'password': 'Password123!',
            'first_name': 'Test',
            'last_name': 'User'
        }
    )
    assert response.status_code == 201
    
    # Try to register the same user again
    response = client.post(
        url_for('auth.register'),
        json={
            'email': 'duplicate@example.com',
            'password': 'Password123!',
            'first_name': 'Test',
            'last_name': 'User'
        }
    )
    assert response.status_code == 400
    data = response.get_json()
    assert 'user_exists' in data['error']


def test_token_refresh_flow(test_client):
    """Test token refresh functionality."""
    client = test_client
    
    # Register and login a user
    client.post(
        url_for('auth.register'),
        json={
            'email': 'refresh@example.com',
            'password': 'Password123!',
            'first_name': 'Test',
            'last_name': 'User'
        }
    )
    
    login_response = client.post(
        url_for('auth.login'),
        json={
            'email': 'refresh@example.com',
            'password': 'Password123!'
        }
    )
    login_data = login_response.get_json()
    
    # Test token refresh
    refresh_response = client.post(
        url_for('auth.refresh'),
        headers={'Authorization': f'Bearer {login_data["refresh_token"]}'}
    )
    assert refresh_response.status_code == 200
    refresh_data = refresh_response.get_json()
    assert 'access_token' in refresh_data
    
    # Test using access token for refresh (should fail)
    invalid_refresh_response = client.post(
        url_for('auth.refresh'),
        headers={'Authorization': f'Bearer {login_data["access_token"]}'}
    )
    assert invalid_refresh_response.status_code == 422


def test_logout_all_devices(test_client):
    """Test logout from all devices."""
    client = test_client
    
    # Register and login a user
    client.post(
        url_for('auth.register'),
        json={
            'email': 'logoutall@example.com',
            'password': 'Password123!',
            'first_name': 'Test',
            'last_name': 'User'
        }
    )
    
    login_response = client.post(
        url_for('auth.login'),
        json={
            'email': 'logoutall@example.com',
            'password': 'Password123!'
        }
    )
    login_data = login_response.get_json()
    
    # Logout from all devices
    logout_response = client.post(
        url_for('auth.logout_all'),
        headers={'Authorization': f'Bearer {login_data["access_token"]}'}
    )
    assert logout_response.status_code == 200
    logout_data = logout_response.get_json()
    assert 'revoked_tokens' in logout_data


def test_protected_route_without_token(test_client):
    """Test accessing protected route without authentication."""
    client = test_client
    
    # Try to access protected route without token
    response = client.get(url_for('auth.get_current_user'))
    assert response.status_code == 401
    
    # Try to access protected route with invalid token
    response = client.get(
        url_for('auth.get_current_user'),
        headers={'Authorization': 'Bearer invalid-token'}
    )
    assert response.status_code == 422


def test_token_verification(test_client):
    """Test token verification endpoint."""
    client = test_client
    
    # Register and login a user
    client.post(
        url_for('auth.register'),
        json={
            'email': 'verify@example.com',
            'password': 'Password123!',
            'first_name': 'Test',
            'last_name': 'User'
        }
    )
    
    login_response = client.post(
        url_for('auth.login'),
        json={
            'email': 'verify@example.com',
            'password': 'Password123!'
        }
    )
    login_data = login_response.get_json()
    
    # Test token verification
    verify_response = client.post(
        url_for('auth.verify_token'),
        headers={'Authorization': f'Bearer {login_data["access_token"]}'}
    )
    assert verify_response.status_code == 200
    verify_data = verify_response.get_json()
    assert 'token_info' in verify_data
    assert verify_data['token_info']['type'] == 'access'


def test_account_lockout_after_failed_attempts(test_client):
    """Test account lockout after multiple failed login attempts."""
    client = test_client
    
    # Register a user
    client.post(
        url_for('auth.register'),
        json={
            'email': 'lockout@example.com',
            'password': 'Password123!',
            'first_name': 'Test',
            'last_name': 'User'
        }
    )
    
    # Make multiple failed login attempts
    for i in range(5):
        response = client.post(
            url_for('auth.login'),
            json={
                'email': 'lockout@example.com',
                'password': 'wrongpassword'
            }
        )
        assert response.status_code == 401
    
    # Next attempt should result in account lockout
    response = client.post(
        url_for('auth.login'),
        json={
            'email': 'lockout@example.com',
            'password': 'wrongpassword'
        }
    )
    assert response.status_code == 401  # First 5 attempts get 401
    
    # Further attempts should show locked account
    response = client.post(
        url_for('auth.login'),
        json={
            'email': 'lockout@example.com',
            'password': 'Password123!'  # Even with correct password
        }
    )
    assert response.status_code == 423  # Account locked


def test_password_change_flow(test_client):
    """Test password change functionality."""
    client = test_client
    
    # Register and login a user
    client.post(
        url_for('auth.register'),
        json={
            'email': 'changepass@example.com',
            'password': 'Password123!',
            'first_name': 'Test',
            'last_name': 'User'
        }
    )
    
    login_response = client.post(
        url_for('auth.login'),
        json={
            'email': 'changepass@example.com',
            'password': 'Password123!'
        }
    )
    login_data = login_response.get_json()
    
    # Test password change
    change_response = client.post(
        url_for('auth.change_password'),
        headers={'Authorization': f'Bearer {login_data["access_token"]}'},
        json={
            'current_password': 'Password123!',
            'new_password': 'NewPassword456!'
        }
    )
    assert change_response.status_code == 200
    
    # Test login with new password
    new_login_response = client.post(
        url_for('auth.login'),
        json={
            'email': 'changepass@example.com',
            'password': 'NewPassword456!'
        }
    )
    assert new_login_response.status_code == 200
    
    # Test login with old password (should fail)
    old_login_response = client.post(
        url_for('auth.login'),
        json={
            'email': 'changepass@example.com',
            'password': 'Password123!'
        }
    )
    assert old_login_response.status_code == 401
