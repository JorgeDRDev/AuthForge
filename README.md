# AuthForge

AuthForge is a secure, Flask-based authentication API designed to support user registration, login, token management, and role-based access control. This project is set up for production readiness with integrated security measures such as HTTPS-only cookies, JWT token management, and rate limiting. 

## Purpose
AuthForge is built to be a foundational authentication system for web applications, providing secure user authentication flows and role management.

## Setup

### Prerequisites
- Python 3.8+
- Flask

### Installation
1. Clone this repository:

   ```bash
   git clone <repository-url>
   cd authforge
   ```

2. Create a virtual environment and activate it:

   ```bash
   python -m venv venv
   . venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install the dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Copy `.env.example` to `.env` and update environment variables as needed:

   ```bash
   cp .env.example .env
   ```

5. Initialize the database:

   ```bash
   flask db upgrade
   ```

### Running the Application

```bash
flask run
```

## Environment Variables
Define all sensitive information such as `SECRET_KEY`, `JWT_SECRET_KEY`, and `DATABASE_URL` in the `.env` file according to your setup.

## API Routes
- `/api/auth/register` (POST): Register a new user.
- `/api/auth/login` (POST): Log in and receive tokens.
- `/api/auth/logout` (POST): Log out of the current session.
- `/api/auth/logout-all` (POST): Log out of all sessions.
- `/api/auth/refresh` (POST): Refresh access token.
- `/api/auth/change-password` (POST): Change user password.

### Example Request/Response
```bash
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "Password123!"
}
```

```json
{
  "message": "Login successful",
  "access_token": "<access_token>",
  "refresh_token": "<refresh_token>"
}
```

## Deployment
Deployment can be done using Docker, directly on a server, or using cloud platforms like Heroku. Ensure environment variables are securely handled across your deployment workflow.

For Heroku/Render/Fly.io:
1. Set up Git and connect your remote repository to the platform
2. Configure environment variables securely
3. Deploy the application using the provided `Procfile`

## Future Improvements
- Email confirmation for new users.
- Multi-factor authentication (MFA).
- Enhanced logging and monitoring features.
