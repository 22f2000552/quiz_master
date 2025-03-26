from app import app
from flask_sqlalchemy import SQLAlchemy 
from werkzeug.security import generate_password_hash
from datetime import datetime

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    passhash = db.Column(db.String(100), nullable=False)  # Store hashed passwords
    is_admin = db.Column(db.Boolean, nullable=False, default=False)  # Fixed db.Boolean
    is_blocked = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(50), nullable=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    username = db.Column(db.String(50), nullable=False, unique=True)  # Fixed db.String(50)
    qualification = db.Column(db.String(50), nullable=False)  # Fixed db.String(50)
    dob = db.Column(db.DateTime, nullable=False)

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(1000), nullable=False)
    qualification = db.Column(db.String(50), nullable=True)  # Fixed db.String(50)

    chapters = db.relationship('Chapter', backref='subject', lazy=True, cascade='all, delete-orphan') 

class Chapter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=True)
    description = db.Column(db.String(1000), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)

    quizes = db.relationship('Quiz', backref='chapter', lazy=True, cascade='all, delete-orphan')

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, nullable=True)
    duration = db.Column(db.Integer, nullable=False)
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapter.id'), nullable=False)
    total_marks = db.Column(db.Integer, nullable=False, default=0)  # New field

    questions = db.relationship('Question', backref='quiz', lazy=True, cascade='all, delete-orphan')

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_statement = db.Column(db.Text, nullable=False)  # Ensured it's not nullable
    option1 = db.Column(db.String(200), nullable=False)
    option2 = db.Column(db.String(200), nullable=False)
    option3 = db.Column(db.String(200), nullable=False)
    option4 = db.Column(db.String(200), nullable=False)
    correct_option = db.Column(db.Integer, nullable=False)
    correct_answer = db.Column(db.String(200), nullable=False)
    marks = db.Column(db.Integer, nullable=False, default=1) 

    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)  

class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    total_scored = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

with app.app_context():
    db.create_all()

    if not User.query.filter_by(is_admin=True).first():
        admin = User(
            email="admin@quizmaster.com",
            username="quizmaster",
            passhash=generate_password_hash("admin123"),
            is_admin=True,
            name="Admin",
            qualification="N/A",
            dob=datetime.strptime("2000-01-01", "%Y-%m-%d")
            )
        db.session.add(admin)
        db.session.commit()
        print("Admin account created!")