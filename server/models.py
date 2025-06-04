from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from werkzeug.security import generate_password_hash, check_password_hash


from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship('Recipe', backref='user', lazy=True)

    @property
    def password(self):
        raise AttributeError("Password is write-only.")

    @password.setter
    def password(self, plain_text_password):
        self._password_hash = generate_password_hash(plain_text_password)

    def authenticate(self, password):
        return check_password_hash(self._password_hash, password)

    # Validations
    @validates('username')
    def validate_username(self, key, value):
        if not value or len(value.strip()) == 0:
            raise ValueError("Username must be provided.")
        return value

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)

    # Foreign key to users table
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    @validates('title')
    def validate_title(self, key, value):
        if not value or not value.strip():
            raise ValueError("Title must be present.")
        return value

    @validates('instructions')
    def validate_instructions(self, key, value):
        if not value or len(value.strip()) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return value