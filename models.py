from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class Community(db.Model):
    __tablename__ = 'communities'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    community_id = db.Column(db.Integer, db.ForeignKey('communities.id'), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')  # user veya admin

    community = db.relationship('Community', backref='users')

class Spending(db.Model):
    __tablename__ = 'spendings'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100))
    description = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    hash = db.Column(db.String(256))
    previous_hash = db.Column(db.String(256))
    block_index = db.Column(db.Integer)

    user = db.relationship('User', backref='spendings')
    deleted = db.Column(db.Boolean, default=False)
    nonce = db.Column(db.Integer, nullable=False, default=0)

class SuperAdmin(db.Model):
    __tablename__ = 'superadmin'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class AdminLimit(db.Model):
     __tablename__ = 'admin_limits'
     id = db.Column(db.Integer, primary_key=True)
     community_id = db.Column(db.Integer, db.ForeignKey('communities.id'), nullable=False)
     month = db.Column(db.Date, nullable=False)
     limit = db.Column(db.Float, nullable=False)