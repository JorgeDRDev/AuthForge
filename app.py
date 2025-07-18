"""
Application entry point for AuthForge API.
Creates and runs the Flask application instance.
"""

import os
from app import create_app

# Create Flask application instance
app = create_app()

if __name__ == '__main__':
    # Run the application in development mode
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug
    )
