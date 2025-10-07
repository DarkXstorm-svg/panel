import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Set up logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///checker_data.db"
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize the app with the extension
db.init_app(app)

# Import models and routes within the app context
# This ensures 'db' is fully initialized before models are defined
with app.app_context():
    # Import models to ensure tables are created
    import models  # noqa: F401
    
    # Create all tables
    db.create_all()
    
    # Initialize default admin user and settings
    from utils import initialize_default_data
    initialize_default_data()
    
    # Import routes after models and db setup
    import routes  # noqa: F401
