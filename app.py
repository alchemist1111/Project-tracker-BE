from flask import Flask, request, make_response, jsonify
from flask_restful import Api, Resource
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity, jwt_required
)
import os
from datetime import datetime, timedelta
from flask import redirect, url_for
import jwt
from config import db, app, Mail, Message
from models import User, Project, ProjectMember, Cohort, Profile, Feedback
from email_validator import validate_email, EmailNotValidError


# Configurations
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "super-secret-key")
app.config['JWT_TOKEN_LOCATION'] = ['headers']
jwt = JWTManager(app)
api=Api(app)
mail = Mail(app)



@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()

class Home(Resource):
    def get(self):
        return {"message":"Welcome to Project Tracker"}

api.add_resource(Home,'/')

# User registration
class UserRegistration(Resource):
  def post(self):
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    is_admin = data.get('is_admin', False)
    project_id = data.get('project_id')

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

        # Add user to project
        project_member = ProjectMember(user_id=user.id, project_id=project_id)
        db.session.add(project_member)
        db.session.commit()

        access_token = create_access_token(identity=user)
        return make_response({"user":user.to_dict(),'access_token': access_token},201)
      
      except Exception as e:
        return {'error': e.args}, 422

    else:
      return make_response({'error':"Email already registered, kindly log in"},401)  

api.add_resource(UserRegistration, '/register', endpoint='/register')  

# User login
class LoginResource(Resource):
    def post(self):
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        project_id = data.get('project_id')

        user = User.query.filter_by(email=email).first()

        if user and user.authenticate(password):
            access_token = create_access_token(identity=user)

            # Check if user is already a member of the project
            if not ProjectMember.query.filter_by(user_id=user.id, project_id=project_id).first():
                # Add user to project
                project_member = ProjectMember(user_id=user.id, project_id=project_id)
                db.session.add(project_member)
                db.session.commit()

            return make_response({"user": user.to_dict(), 'access_token': access_token}, 201)
        else:
            return make_response({'error': "Unauthorized"}, 401)
        
api.add_resource(LoginResource, '/login', endpoint="login")

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
                "github_url": project.github_url,
                "users": [{
                    "id": member.user.id,
                    "username": member.user.username
                } for member in project.project_members]  # Correct iteration over project.users
            } for project in projects]
            return make_response(jsonify(projects_list), 200)
        else:
            project = Project.query.get_or_404(project_id)
            project_dict = {
                "id": project.id,
                "name": project.name,
                "description": project.description,
                "github_url": project.github_url,
                "users": [{
                    "id": member.user.id,
                    "username": member.user.username
                } for member in project.project_members]  # Include users in the single project response
            }
            return make_response(jsonify(project_dict), 200)
    
    # Create a new project
    def post(self):
        
        data = request.get_json()

        new_project = Project(
            name=data['name'],
            description=data.get('description', ''),
            github_url=data.get('github_url', '')  
        )

        db.session.add(new_project)
        db.session.commit()

        project_dict = {
            "id": new_project.id,
            "name": new_project.name,
            "description": new_project.description,
            "github_url": new_project.github_url
        }
        return make_response(jsonify(project_dict), 201)


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

class ProjectMemberResource(Resource):
    # Get a list of project members
    def get(self, project_member_id=None):
        if project_member_id is None:
            project_members = ProjectMember.query.all()
            project_members_list = [{
                "id": project_member.id,
                "user_id": project_member.user_id,
                "username": project_member.user.username,
                "project_id": project_member.project_id
            }for project_member in project_members]
            return make_response(jsonify(project_members_list), 200)
        else:
            project_member = ProjectMember.query.get_or_404(project_member_id)
            project_member_dict = {
                "id": project_member.id,
                "user_id": project_member.user_id,
                "username": project_member.user.username,
                "project_id": project_member.project_id
            }
            return make_response(jsonify(project_member_dict), 200)
    
    # Create a new project member
    def post(self):
        data = request.get_json()

        new_project_member = ProjectMember(
            user_id=data['user_id'],
            project_id=data['project_id']
        )

        db.session.add(new_project_member)
        db.session.commit()

        project_member_dict = {
            "id": new_project_member.id,
            "user_id": new_project_member.user_id,
            "project_id": new_project_member.project_id
        }
        return make_response(jsonify(project_member_dict), 201)

    # Update an existing project member
    def put(self, project_member_id):
        project_member = ProjectMember.query.get_or_404(project_member_id)
        data = request.get_json()

        project_member.user_id = data.get('user_id', project_member.user_id)
        project_member.project_id = data.get('project_id', project_member.project_id)

        db.session.commit()

        project_member_dict = {
            "id": project_member.id,
            "user_id": project_member.user_id,
            "project_id": project_member.project_id
        }
        return make_response(jsonify(project_member_dict), 200)

    # Delete an existing project member
    def delete(self, project_member_id):
        project_member = ProjectMember.query.get_or_404(project_member_id)
        db.session.delete(project_member)
        db.session.commit()
        return make_response(jsonify({"message": "Project member deleted successful"}), 200)

api.add_resource(ProjectMemberResource, '/project_members', '/project_members/<int:project_member_id>')


class CohortResource(Resource):
   # Get a list of all cohorts
   def get(self, cohort_id=None):
    if cohort_id is None:
        cohorts = Cohort.query.all()
        cohorts_list = [{
            "id": cohort.id,
            "name": cohort.name,
            "projects": [{
                "id": project.id,
                "name": project.name,
                "description": project.description,
                "github_url": project.github_url,
                "project_members": [{
                    "id": project_member.id,
                    "user_id": project_member.user_id,
                    "project_id": project_member.project_id
                } for project_member in project.project_members]
            } for project in cohort.projects]
        } for cohort in cohorts]
        return jsonify(cohorts_list)
    else:
        cohort = Cohort.query.get_or_404(cohort_id)
        cohort_dict = {
            "id": cohort.id,
            "name": cohort.name,
            "projects": [{
                "id": project.id,
                "name": project.name,
                "description": project.description,
                "github_url": project.github_url,
                "project_members": [{
                    "id": project_member.id,
                    "user_id": project_member.user_id,
                    "project_id": project_member.project_id
                } for project_member in project.project_members]
            } for project in cohort.projects]
        }
        return jsonify(cohort_dict)
    
    # Create a new cohort
   def post(self):
        data = request.get_json()
        new_cohort = Cohort(name=data['name'])
        db.session.add(new_cohort)
        db.session.commit()

        cohort_dict = {
            "id": new_cohort.id,
            "name": new_cohort.name
        }
        return make_response(jsonify(cohort_dict), 201)
   
   # Update an existing cohort
   def put(self, cohort_id):
       cohort = Cohort.query.get_or_404(cohort_id)
       data = request.get_json()

       cohort.name = data.get('name', cohort.name)
       db.session.commit()

       cohort_dict = {
           "id": cohort.id,
           "name": cohort.name
       }
       return jsonify(cohort_dict)
   
   # Delete an existing cohort
   def delete(self, cohort_id):
       cohort = Cohort.query.get_or_404(cohort_id)
       db.session.delete(cohort)
       db.session.commit()
       return make_response(jsonify({"message": "Cohort deleted successfully"}), 200)

api.add_resource(CohortResource, '/cohorts', '/cohorts/<int:cohort_id>')


class ProfileResource(Resource):
    def get(self, user_id):
        user = User.query.get_or_404(user_id)
        user_profile = {
            "id": user.id,
            "username": user.username,
            "email": user.email
        }
        return make_response(jsonify(user_profile), 200)

api.add_resource(ProfileResource, '/profile/<int:user_id>')

class UserByEmail(Resource):
    def post(self):
        try:
            data = request.get_json()
            email = data.get('email')
            
            if not email:
                return make_response({"message": "Email is required"}, 400)
            
            user = User.query.filter_by(email=email).first()
            
            if user:
                access_token = create_access_token(identity=user)
                response = make_response({
                    "user": user.to_dict(),
                    "access_token": access_token
                }, 200)
            else:
                response = make_response({"message": "User not found"}, 404)
            
        except Exception as e:
            response = make_response({"message": f"An error occurred: {str(e)}"}, 500)
        
        return response

api.add_resource(UserByEmail, '/userByEmail', endpoint="userByEmail")

# Generate Invite Token
def generate_invite_token(email, project_id):
    token = jwt.encode({
        'sub': {
            'email': email,
            'project_id': project_id
        },
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config["JWT_SECRET_KEY"], algorithm='HS256')
    return token

# Email Endpoint
class SendInvite(Resource):
    @jwt_required()
    def post(self):
        try:
            user_id = get_jwt_identity()
            sender_user = User.query.filter_by(id=user_id).first()
            
            if not sender_user or not sender_user.email:
                return jsonify({"error": "Sender not found or email not set"}), 400
            
            sender_email = sender_user.email
            data = request.get_json()
            emails = data.get('emails', [])
            project_id = data.get('project_id')
            
            # Validate that emails and project_id are provided
            if not emails or not project_id:
                return jsonify({"error": "Emails and project ID are required"}), 400

            for email in emails:
                if not email:
                    continue
                try:
                    valid = validate_email(email)
                    email = valid.email  # Normalized email

                    # Generate token and invite link
                    token = generate_invite_token(email, project_id)
                    invite_link = url_for('handle_invite', token=token, _external=True)

                    # Send email
                    msg = Message(
                        'Project Invitation',
                        sender=sender_email,
                        recipients=[email]
                    )
                    msg.body = f'You have been invited to join the project. Click here: {invite_link}'
                    mail.send(msg)

                except EmailNotValidError as e:
                    app.logger.warning(f"Invalid email {email}: {str(e)}")
                    continue
                except Exception as email_exception:
                    app.logger.error(f"Failed to send invite to {email}: {str(email_exception)}")
                    continue

            return jsonify({"message": "Invitations sent!"}), 200

        except Exception as e:
            app.logger.error(f"Error sending invite: {str(e)}")
            return jsonify({"error": str(e)}), 500

api.add_resource(SendInvite, '/send_invite')

# Endpoint to handle invite link
@app.route('/invite/<token>', methods=['GET'])
def handle_invite(token):
    try:
        # Decode the token
        decoded_token = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
        email = decoded_token['email']
        project_id = decoded_token['project_id']
        
        # Check if user exists
        user = User.query.filter_by(email=email).first()
        if user:
            # User exists, redirect to login with project_id
            return redirect(url_for('login', email=email, project_id=project_id))
        else:
            # User does not exist, redirect to signup with project_id
            return redirect(url_for('register', email=email, project_id=project_id))
    
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'The invitation link has expired.'}), 400
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid invitation link.'}), 400



class Feedback(Resource):
   pass

if __name__ == '__main__':
    app.run(debug=True)