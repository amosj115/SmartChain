import os


class Config:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, os.pardir))
    SECRET_KEY = os.environ.get("SMARTCHAIN_SECRET_KEY", "dev-secret-key")
    ENV = os.environ.get("SMARTCHAIN_ENV", "development")
    DEFAULT_DB_PATH = os.path.join(PROJECT_ROOT, "smartchain.db")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "SMARTCHAIN_DATABASE_URI",
        f"sqlite:///{DEFAULT_DB_PATH.replace('\\', '/')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEV_ACCESS_ENABLED = ENV == "development"
    APP_NAME = "SmartChain"
    APP_VERSION = "1.0.0"
