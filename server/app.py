#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import Bcrypt

from consefig import app, db, api
from models import User, Recipe

# Initialize Bcrypt
bcrypt = Bcrypt(app)
app.secret_key = 'your-secret-key'  # Set a secret key for session support


# ----------- SIGNUP -----------
class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')

        errors = []
        if not username:
            errors.append("Username is required.")
        if not password:
            errors.append("Password is required.")

        if errors:
            return {"errors": errors}, 422

        try:
            user = User(username=username, image_url=image_url, bio=bio)
            user.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return user.to_dict(), 201
        except IntegrityError:
            db.session.rollback()
            return {"errors": ["Username already exists."]}, 422


# ----------- CHECK SESSION -----------
class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                return user.to_dict(), 200
        return {"error": "Unauthorized"}, 401


# ----------- LOGIN -----------
class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        return {"error": "Unauthorized"}, 401


# ----------- LOGOUT -----------
class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session.pop('user_id')
            return {}, 204
        return {"error": "Unauthorized"}, 401

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {"error": "Unauthorized"}, 401

        recipes = Recipe.query.all()
        return [
            {
                "id": r.id,
                "title": r.title,
                "instructions": r.instructions,
                "minutes_to_complete": r.minutes_to_complete,
                "user": r.user.to_dict()
            }
            for r in recipes
        ], 200

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {"error": "Unauthorized"}, 401

        data = request.get_json()
        title = data.get('title')
        instructions = data.get('instructions')
        minutes = data.get('minutes_to_complete')

        errors = []
        if not title:
            errors.append("Title is required.")
        if not instructions:
            errors.append("Instructions are required.")
        if not isinstance(minutes, int) or minutes <= 0:
            errors.append("Minutes to complete must be a positive integer.")

        if errors:
            return {"errors": errors}, 422

        try:
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes,
                user_id=user_id
            )
            db.session.add(recipe)
            db.session.commit()

            return {
                "id": recipe.id,
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user": recipe.user.to_dict()
            }, 201
        except Exception as e:
            db.session.rollback()
            return {"errors": ["Something went wrong."]}, 422


# Register Resources with API
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


# Run the app
if __name__ == '__main__':
    app.run(port=5555, debug=True)
