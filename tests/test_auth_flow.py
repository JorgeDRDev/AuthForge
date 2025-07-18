"""
Integration tests for AuthForge API's authentication endpoints.
Test suites include user registration, login, protected routes, and logout.
"""

import pytest
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


def register_user(client, email, password, first_name='Test', last_name='User'):
    """Helper function to register a new user."""
    return client.post(
        url_for('auth.register'),
        json={
            'email': email,
            'password': password,
            'first_name': first_name,
            'last_name': last_name
        }
    )

def login_user(client, email, password):
    """Helper function to log in a user and return tokens."""
    response = client.post(
        url_for('auth.login'),
        json={
            'email': email,
            'password': password
        }
    )
    return response.get_json()


def test_register_login_logout_flow(test_client):
    """Test user registration, login, access protected route, and logout."""
    client = test_client

    # Register a new user
    register_response = register_user(client, 'testuser@example.com', 'Password1!')
    assert register_response.status_code == 201
    register_data = register_response.get_json()
    assert 'access_token' in register_data
    assert 'refresh_token' in register_data

    # Login with registered user
    login_data = login_user(client, 'testuser@example.com', 'Password1!')
    assert 'access_token' in login_data
    assert 'refresh_token' in login_data

    # Access protected route
    protected_response = client.get(
        url_for('auth.get_current_user'),
        headers={'Authorization': f'Bearer {login_data['access_token']}'}
    )
    assert protected_response.status_code == 200
    protected_data = protected_response.get_json()
    assert protected_data['user']['email'] == 'testuser@example.com'

    # Logout
    logout_response = client.post(
        url_for('auth.logout'),
        headers={'Authorization': f'Bearer {login_data['access_token']}'}
    )
    assert logout_response.status_code == 200
    logout_data = logout_response.get_json()
    assert logout_data['message'] == 'Logged out successfully'

