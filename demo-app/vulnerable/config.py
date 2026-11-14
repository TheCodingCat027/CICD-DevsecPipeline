# WARNING: This file contains INTENTIONALLY FAKE credentials for security testing.
# These are NOT real AWS credentials. They are planted as V1 for Gitleaks detection testing.
# DO NOT deploy this application. DO NOT use these values in any real system.
# See demo-app/README.md for details.

import os

# V1: Hardcoded fake AWS credentials (intentionally planted for Gitleaks detection)
# These match the AWS key pattern but are completely fabricated.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"      # fake - pattern: AKIA + 16 uppercase alphanum
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # fake

# Database configuration
DATABASE_URL = "sqlite:///./notes.db"
SECRET_KEY = "dev-only-not-secret-change-me"
DEBUG = True
