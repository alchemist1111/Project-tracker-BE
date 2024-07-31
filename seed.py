from config import db, app, bcrypt
from sqlalchemy.exc import IntegrityError
from models import User

def hash_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')

def seed_data():
    with app.app_context():
        # Clear existing data
        db.session.query(User).delete()

        # Add users
        users = [
            User(username="John Doe", email="john@gmail.com", _password_hash=hash_password("Password@123"), is_admin=True),
            User(username="Jane Smith", email="jane@gmail.com", _password_hash=hash_password("Password@124"), is_admin=False),
            User(username="Bob Johnson", email="bob@gmail.com", _password_hash=hash_password("Password@125"), is_admin=False),
            User(username="Glen Brad", email="glen@gmail.com", _password_hash=hash_password("Password@126"), is_admin=False),
            User(username="Alice Johnson", email="alice@gmail.com", _password_hash=hash_password("Password@127"), is_admin=False),
            User(username="David Johnson", email="david@gmail.com", _password_hash=hash_password("Password@128"), is_admin=True),
            User(username="Emily Johnson", email="emily@gmail.com", _password_hash=hash_password("Password@129"), is_admin=False),
            User(username="Michael Johnson", email="michael@gmail.com", _password_hash=hash_password("Password@130"), is_admin=False),
            User(username="Sarah Johnson", email="sarah@gmail.com", _password_hash=hash_password("Password@131"), is_admin=False),
            User(username="Daniel Johnson", email="daniel@gmail.com", _password_hash=hash_password("Password@132"), is_admin=False)
        ]
        db.session.add_all(users)

        try:
            # Commit all changes
            db.session.commit()
            print("Database seeded with new data!")
        except IntegrityError:
            db.session.rollback()
            print("Integrity error occurred. Database rollback.")

if __name__ == "__main__":
    seed_data()
