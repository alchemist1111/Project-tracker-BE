from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.orm import validates, relationship
from sqlalchemy.ext.associationproxy import association_proxy
from config import db, bcrypt
from datetime import datetime
import re


# User model
class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    cohort_id = db.Column(db.Integer, db.ForeignKey('cohorts.id'))

    # Relationships
    projects = db.relationship('Project', back_populates="user", lazy='dynamic')
    project_members = db.relationship('ProjectMember', back_populates="user", lazy='dynamic')
    cohort = db.relationship('Cohort', back_populates='users', lazy='joined')
    profile = db.relationship('Profile', back_populates="user", cascade="all, delete-orphan", uselist=False,single_parent=True,lazy='joined'
    )

    # Add serialize rules
    serialize_rules = ("-projects", "-_password_hash", "-cohort.users", "-project_members", "-profile.user")

    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password is not a readable attribute')
  
    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(password.encode("utf-8"))
        self._password_hash = password_hash.decode("utf-8")

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode("utf-8")) 

    def __repr__(self):
        return f'<User, id={self.id}, username={self.username}, email={self.email}, admin={self.is_admin}>'


class Project(db.Model, SerializerMixin):
    __tablename__ = 'projects'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)
    description = db.Column(db.String, nullable=True)
    github_url = db.Column(db.String, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    cohort_id = db.Column(db.Integer, db.ForeignKey('cohorts.id'))

    # Relationships
    user = db.relationship('User', back_populates='projects', lazy='joined')
    project_members = db.relationship('ProjectMember', back_populates='project', lazy='dynamic') 
    cohort = db.relationship('Cohort', back_populates='projects', lazy='joined')

    # Add serialize rules
    serialize_rules = ("-user.projects", "-project_members.project", "-cohort.projects")

    def __repr__(self):
        return f'<Project, id={self.id}, name={self.name}, github_url={self.github_url}>'


class ProjectMember(db.Model, SerializerMixin):
    __tablename__ = 'project_members'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'))

    # Relationships
    user = db.relationship('User', back_populates='project_members', lazy='joined')
    project = db.relationship('Project', back_populates='project_members', lazy='joined')

    # Add serialize rules
    serialize_rules = ("-user.project_members", "-project.project_members")

    def __repr__(self):
        return f'<ProjectMember, id={self.id}, user_id={self.user_id}, project_id={self.project_id}>'


class Cohort(db.Model, SerializerMixin):
    __tablename__ = 'cohorts'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)

    # Relationships
    users = db.relationship('User', back_populates='cohort', lazy='dynamic')
    projects = db.relationship('Project', back_populates='cohort', lazy='dynamic')

    # Add serialize rules
    serialize_rules = ("-users", "-projects")

    def __repr__(self):
        return f'<Cohort, id={self.id}, name={self.name}>'


class Profile(db.Model, SerializerMixin):
    __tablename__ = 'profiles'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Relationship
    user = db.relationship('User', back_populates='profile', lazy='joined')

    # Add serialize rules
    serialize_rules = ("user.username", "user.email")

    def __repr__(self):
        return f'<Profile, id={self.id}, user_id={self.user_id}>'


class Feedback(db.Model, SerializerMixin):
    __tablename__ = 'feedbacks'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    message = db.Column(db.String, nullable=False)

    def __repr__(self):
        return f'<Feedback, id={self.id}, name={self.name}, email={self.email}>'
