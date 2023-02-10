# database connection parameters
# template for settings.py
# CAUTION: exclude settings.py from versioning in .gitignore

HOST = "YourHostname"
USER = "YourUsername"
PASSWD = "YourPassword"
DB = "YourDatabase"

# keys
PASSWORD = b"YourPassword"
PRIVATE_KEY = b"""YourPrivateKey"""
PUBLIC_KEY = b"""YourPublicKEY"""

# Google Auth-Client
GOOGLE_CLIENT_ID = "YourGoogleAuthClientID"
GOOGLE_CLIENT_KEY = "YourGoogleAuthClientKey"
GOOGLE_DISCOVERY_URL = ("https://accounts.google.com/.well-known/openid-configuration")

EXPIRY_TIME_SECONDS = 60

DEBUG_MODE = True     # disable DEBUG_MODE in productive environment