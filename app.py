from flask import Flask, request, make_response, jsonify
from flask_restful import Api, Resource
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity, jwt_required
)
import os
from config import db, app
from models import User, Project, ProjectMember, Cohort, Profile, Feedback

# Configurations
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "super-secret-key")
app.config['JWT_TOKEN_LOCATION'] = ['headers']
jwt = JWTManager(app)
api=Api(app)


@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()

# User registration
class UserRegistration(Resource):
  def post(self):
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    is_admin = data.get('is_admin', False)

    user = User.query.filter_by(email=email).first()

    if not user:
      try:
        user = User(
          username=username,
          email=email,
          is_admin=is_admin
        )
        user.password_hash = password
        db.session.add(user)
        db.session.commit()

        access_token = create_access_token(identity=user)
        return make_response({"user":user.to_dict(),'access_token': access_token},201)
      
      except Exception as e:
        return {'error': e.args}, 422

    else:
      return make_response({'error':"Email already registered, kindly log in"},401)  

api.add_resource(UserRegistration, '/register', endpoint='/register')  

# User login
class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(email=data.get('email')).first()
        if user:
            if user.authenticate(data.get('password')):
                access_token = create_access_token(identity=user)
                response = make_response({"user":user.to_dict(),'access_token': access_token},201)
                return response
            else:
                 return make_response({'error':"Incorrect password"},401)
        else:
             return make_response({'error':"Unauthorized"},401)
        
api.add_resource(Login,'/login',endpoint="login")

# User CRUD operations
class UserResource(Resource):
    # Get all users
    def get(self, user_id=None):
        if user_id:
            user = User.query.get_or_404(user_id)
            user_dict = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin
            }
            return make_response(jsonify(user_dict), 200)
        else:
            users = User.query.all()
            users_list = [{
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin
            } for user in users]
            return make_response(jsonify(users_list), 200)


    # Update user
    def put(self, user_id):
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        user.username = data.get('username', user.username)
        user.email = data.get('email', user.email)
        user.is_admin = data.get('is_admin', user.is_admin)
        
        db.session.commit()
        
        user_dict = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin
        }
        return make_response(jsonify(user_dict), 200)
    
    # Delete user
    def delete(self, user_id):
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return make_response(jsonify({'message': 'User deleted successfully'}), 200)

api.add_resource(UserResource, '/users', '/users/<int:user_id>')    


# Project CRUD operations
class ProjectResource(Resource):
    # Get a list of projects or a specific project
    def get(self, project_id=None):
        if project_id is None:
            projects = Project.query.all()
            projects_list = [{
                "id": project.id,
                "name": project.name,
                "description": project.description,
                "github_url": project.github_url
            } for project in projects]
            return make_response(jsonify(projects_list), 200)
        else:
            project = Project.query.get_or_404(project_id)
            project_dict = {
                "id": project.id,
                "name": project.name,
                "description": project.description,
                "github_url": project.github_url
            }
            return make_response(jsonify(project_dict), 200)
    
    # Create a new project
    def post(self):
        pass


    # Update an existing project
    def put(self, project_id):
        project = Project.query.get_or_404(project_id)
        data = request.get_json()

        project.name = data.get('name', project.name)
        project.description = data.get('description', project.description)
        project.github_url = data.get('github_url', project.github_url)

        db.session.commit()

        project_dict = {
            "id": project.id,
            "name": project.name,
            "description": project.description,
            "github_url": project.github_url
        }
        return make_response(jsonify(project_dict), 200)

    # Delete an existing project
    def delete(self, project_id):
        project = Project.query.get_or_404(project_id)
        db.session.delete(project)
        db.session.commit()
        return make_response(jsonify({"message": "Project deleted successful"}), 200) 

api.add_resource(ProjectResource, '/projects', '/projects/<int:project_id>')      

class ProjectMember(Resource):
   pass

class Cohort(Resource):
   pass


class Profile(Resource):
   pass

class Feedback(Resource):
   pass

if __name__ == '__main__':
    app.run(debug=True)