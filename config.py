import os
from dotenv import load_dotenv
from urllib.parse import quote_plus

# Load environment variables from .env file
load_dotenv()

basedir = os.path.abspath(os.path.dirname(__file__))

# class Config:
#     SECRET_KEY = os.getenv('SECRET_KEY', 'your_default_secret_key')

#     SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(basedir, 'instance', 'inventory.db')}"
#     SQLALCHEMY_TRACK_MODIFICATIONS = False

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your_default_secret_key')

    # Prefer Render/12-factor style DATABASE_URL when present.
    _database_url = os.getenv('DATABASE_URL')
    if _database_url:
        if _database_url.startswith('postgres://'):
            _database_url = _database_url.replace('postgres://', 'postgresql://', 1)
        SQLALCHEMY_DATABASE_URI = _database_url
    # Fallback: construct Postgres URI from POSTGRES_* variables.
    elif os.getenv('POSTGRES_HOST'):
        POSTGRES_USER = os.getenv('POSTGRES_USER', '')
        POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', '')
        POSTGRES_HOST = os.getenv('POSTGRES_HOST', '')
        POSTGRES_PORT = os.getenv('POSTGRES_PORT', '5432')
        POSTGRES_DB = os.getenv('POSTGRES_DB', '')
        SQLALCHEMY_DATABASE_URI = (
            f"postgresql+psycopg2://{POSTGRES_USER}:{quote_plus(POSTGRES_PASSWORD)}@"
            f"{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
        )
    # Fallback: MySQL via MYSQL_* variables (local/dev compatibility).
    else:
        MYSQL_USER = os.getenv('MYSQL_USER', 'root')
        MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD', 'root')
        MYSQL_HOST = os.getenv('MYSQL_HOST', '127.0.0.1')
        MYSQL_PORT = os.getenv('MYSQL_PORT', '3306')
        MYSQL_DB = os.getenv('MYSQL_DB', 'assets')
        SQLALCHEMY_DATABASE_URI = (
            f"mysql+pymysql://{MYSQL_USER}:{quote_plus(MYSQL_PASSWORD)}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}"
        )

    SQLALCHEMY_TRACK_MODIFICATIONS = False
