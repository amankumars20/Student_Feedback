#!/usr/bin/env python3
"""
Cross-platform script to run the Flask application with environment variables loaded from .env file.
This replaces the set_aws_credentials.bat file and works on Windows, macOS, and Linux.
"""

import os
import sys
from dotenv import load_dotenv

def main():
    print("=" * 50)
    print("Flask Feedback Application Launcher")
    print("=" * 50)
    
    # Load environment variables from .env file
    print("Loading environment variables from .env file...")
    if not os.path.exists('.env'):
        print("ERROR: .env file not found!")
        print("Please create a .env file with your AWS credentials.")
        print("You can use .env.example as a template.")
        sys.exit(1)
    
    load_dotenv()
    
    # Verify required environment variables
    required_vars = [
        'AWS_ACCESS_KEY_ID',
        'AWS_SECRET_ACCESS_KEY',
        'AWS_REGION',
        'S3_BUCKET',
        'DYNAMODB_TABLE',
        'ADMIN_TABLE'
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print(f"ERROR: Missing required environment variables: {', '.join(missing_vars)}")
        print("Please check your .env file and ensure all required variables are set.")
        sys.exit(1)
    
    print("✓ Environment variables loaded successfully!")
    print()
    print("Configuration:")
    print(f"  AWS Region: {os.getenv('AWS_REGION')}")
    print(f"  S3 Bucket: {os.getenv('S3_BUCKET')}")
    print(f"  DynamoDB Table: {os.getenv('DYNAMODB_TABLE')}")
    print(f"  Admin Table: {os.getenv('ADMIN_TABLE')}")
    print()
    print("Starting Flask application...")
    print("=" * 50)
    
    # Import and run the Flask app
    try:
        from app import app
        app.run(debug=os.getenv('FLASK_DEBUG', 'True').lower() == 'true')
    except ImportError as e:
        print(f"ERROR: Could not import Flask app: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to start Flask app: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
