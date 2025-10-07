#!/usr/bin/env python3
"""
Database setup script - creates all tables and initializes default data
Run this script to set up the database for the first time
"""

from app import app, db
from utils import initialize_default_data

def setup_database():
    """Set up the database with all required tables and default data"""
    with app.app_context():
        print("Creating database tables...")
        
        # Create all tables
        db.create_all()
        print("✓ Database tables created successfully")
        
        # Initialize default data
        print("Initializing default data...")
        initialize_default_data()
        print("✓ Default admin user and settings initialized")
        
        print("\nDatabase setup complete!")
        print(f"Admin username: ASH")
        print(f"Admin password: Joshua091003@")
        print("Please change the default password after first login.")

if __name__ == '__main__':
    setup_database()
