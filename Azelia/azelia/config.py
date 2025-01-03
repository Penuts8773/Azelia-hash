import os

class Config:
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'default_secret_key')
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = False
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = 'pookie090102'
    MYSQL_DB = 'azelia'
    USER_TABLE_NAME = 'leandb'
    PEPPER_SECRET = os.getenv('PEPPER_SECRET', 'default_pepper')
