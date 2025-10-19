#!/usr/bin/env python3
"""
Production-ready startup script for Happy Deal Transit ERP
"""
import os
import sys

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app, init_db
except ImportError as e:
    print(f"Error importing app: {e}")
    print("Make sure app.py is in the same directory and all dependencies are installed")
    sys.exit(1)

# Initialize database on startup (for first deployment)
try:
    with app.app_context():
        init_db()
except Exception as e:
    print(f"Database initialization warning: {e}")

# Export app for Vercel serverless
application = app

def main():
    try:
        # Get configuration from environment variables
        host = os.environ.get('FLASK_HOST', '0.0.0.0')
        port = int(os.environ.get('FLASK_PORT', 5000))
        debug = os.environ.get('FLASK_DEBUG', 'False').lower() in ['true', '1', 'yes']
        
        print("="*50)
        print("Happy Deal Transit ERP Backend")
        print("="*50)
        print(f"Starting server at: http://{host}:{port}")
        print(f"Debug mode: {'ON' if debug else 'OFF'}")
        print(f"API Test: http://{host}:{port}/api/test")
        print(f"Login with: admin@hdtransit.com / admin123")
        print("="*50)
        
        # Start the Flask application
        app.run(
            host=host,
            port=port,
            debug=debug,
            threaded=True,
            use_reloader=debug
        )
        
    except KeyboardInterrupt:
        print("\nServer stopped gracefully")
    except Exception as e:
        print(f"Error starting server: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()