"""
Fixed configuration - reads secrets from environment variables.
See .env.example for required variables.
"""
import os

# Fixed V1: Read credentials from environment, not hardcoded
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID', '')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY', '')

DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///./notes.db')
SECRET_KEY = os.environ.get('SECRET_KEY', 'CHANGE-ME-IN-PRODUCTION')
DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'
