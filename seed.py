from config import db, app, bcrypt
from sqlalchemy.exc import IntegrityError
from models import User, Project, ProjectMember, Cohort, Profile, Feedback

def hash_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')

def seed_data():
    with app.app_context():
        # Clear existing data
        db.session.query(User).delete()
        db.session.query(Project).delete()
        db.session.query(ProjectMember).delete()
        db.session.query(Cohort).delete()
        db.session.query(Profile).delete()

        # Add users
        users = [
            User(username="John Doe", email="john@gmail.com", _password_hash=hash_password("Password@123"), is_admin=True, cohort_id=1),
            User(username="Jane Smith", email="jane@gmail.com", _password_hash=hash_password("Password@124"), is_admin=False, cohort_id=2),
            User(username="Bob Johnson", email="bob@gmail.com", _password_hash=hash_password("Password@125"), is_admin=False, cohort_id=3),
            User(username="Glen Brad", email="glen@gmail.com", _password_hash=hash_password("Password@126"), is_admin=False, cohort_id=4),
            User(username="Alice Johnson", email="alice@gmail.com", _password_hash=hash_password("Password@127"), is_admin=False, cohort_id=5),
            User(username="David Johnson", email="david@gmail.com", _password_hash=hash_password("Password@128"), is_admin=True, cohort_id=6),
            User(username="Emily Johnson", email="emily@gmail.com", _password_hash=hash_password("Password@129"), is_admin=False, cohort_id=1),
            User(username="Michael Johnson", email="michael@gmail.com", _password_hash=hash_password("Password@130"), is_admin=False, cohort_id=3),
            User(username="Sarah Johnson", email="sarah@gmail.com", _password_hash=hash_password("Password@131"), is_admin=False, cohort_id=5),
            User(username="Daniel Johnson", email="daniel@gmail.com", _password_hash=hash_password("Password@132"), is_admin=False, cohort_id=2)
        ]
        db.session.add_all(users)

        # Add projects
        projects = [
            Project(name="Project 1", description="This is project 1", github_url="https://github.com/project1", user_id=1, cohort_id=1),
            Project(name="Project 2", description="This is project 2", github_url="https://github.com/project2", user_id=2, cohort_id=1),
            Project(name="Project 3", description="This is project 3", github_url="https://github.com/project3", user_id=3, cohort_id=2),
            Project(name="Project 4", description="This is project 4", github_url="https://github.com/project4", user_id=4, cohort_id=2),
            Project(name="Project 5", description="This is project 5", github_url="https://github.com/project5", user_id=5, cohort_id=3),
            Project(name="Project 6", description="This is project 6", github_url="https://github.com/project6", user_id=6, cohort_id=3),
            Project(name="Project 7", description="This is project 7", github_url="https://github.com/project7", user_id=7, cohort_id=4),
            Project(name="Project 8", description="This is project 8", github_url="https://github.com/project8", user_id=8, cohort_id=4)
        ]
        db.session.add_all(projects)

        # Add project members
        project_members = [
            ProjectMember(user_id=1, project_id=1),
            ProjectMember(user_id=2, project_id=2),
            ProjectMember(user_id=3, project_id=3),
            ProjectMember(user_id=4, project_id=4),
            ProjectMember(user_id=5, project_id=5),
            ProjectMember(user_id=6, project_id=1),
            ProjectMember(user_id=7, project_id=2),
            ProjectMember(user_id=8, project_id=3),
            ProjectMember(user_id=9, project_id=4),
            ProjectMember(user_id=10, project_id=5)
        ]
        db.session.add_all(project_members)

        # Add cohorts
        cohorts = [
            Cohort(name="FT05"),
            Cohort(name="FT06"),
            Cohort(name="FT07"),
            Cohort(name="FT08"),
            Cohort(name="FT09"),
            Cohort(name="FT10")
        ]
        db.session.add_all(cohorts)

        # Add profiles
        profiles = [
            Profile(user_id=1),
            Profile(user_id=2),
            Profile(user_id=3),
            Profile(user_id=4),
            Profile(user_id=5),
            Profile(user_id=6)
        ]
        db.session.add_all(profiles)

        # Add feedbacks
        feedbacks = [
            Feedback(name="John Doe", email="john@gmail.com", message="This is a great project!"),
            Feedback(name="Jane Smith", email="jane@gmail.com", message="I'm excited to contribute!"),
            Feedback(name="Bob Johnson", email="bob@gmail.com", message="This is an amazing project!"),
            Feedback(name="Glen Brad", email="glen@gmail.com", message="I'm looking forward to working on this project."),
            Feedback(name="Alice Johnson", email="alice@gmail.com", message="I'm really proud of this project!"),
            Feedback(name="David Johnson", email="david@gmail.com", message="This project has been a great opportunity for me to learn.")
        ]
        db.session.add_all(feedbacks)
        

        try:
            # Commit all changes
            db.session.commit()
            print("Database seeded with new data!")
        except IntegrityError:
            db.session.rollback()
            print("Integrity error occurred. Database rollback.")

if __name__ == "__main__":
    seed_data()
