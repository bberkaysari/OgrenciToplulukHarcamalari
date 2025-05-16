class Config:
    SECRET_KEY = 'supersecretkey'
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:123456@localhost:5432/blockchain_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_SAMESITE = "Lax"        # <-- değiştirildi
    SESSION_COOKIE_SECURE = False          # <-- http için
    SESSION_TYPE = 'filesystem'
    SESSION_COOKIE_HTTPONLY = True