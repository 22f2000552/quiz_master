from flask import render_template, request, redirect, url_for, flash, session
from app import app
from werkzeug.security import  generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from models import *

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash("Access denied. Admins only.")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# 👋 **Logout Route**
@app.route("/logout")
def logout():
    session.pop("user_id", None)  # Remove session data
    flash("Logged out successfully!", "info")
    return redirect(url_for("index"))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        dob = request.form['dob']
        qualification = request.form.get('qualification', 'Not Provided')  # Default value if missing



        # Hash the password
        hashed_password = generate_password_hash(password)

        # Convert dob to datetime object
        dob_date = datetime.strptime(dob, '%Y-%m-%d')

        # Check if email or username already exists
        existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
        if existing_user:
            flash("Email or username already exists. Try again!", "danger")
            return redirect(url_for('signup'))

        # Create new user
        new_user = User(name=name, email=email, username=username, passhash=hashed_password, dob=dob_date, qualification=qualification)
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully! You can now login.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect if not logged in

    user = User.query.get(session['user_id'])  # Fetch logged-in user
    return render_template('dashboard.html', user=user)


@app.route('/admin')
@admin_required
def admin():
    user = User.query.get(session.get('user_id'))  # Use .get() to avoid KeyError
    if not user or not user.is_admin:  # Prevent NoneType error
        flash("Access denied. Admins only.")
        return redirect(url_for('index'))
    return render_template("admin_dashboard.html", user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.passhash, password):
            flash("Invalid email or password", "danger")
            return redirect(url_for('login'))

        if user.is_blocked:  # 🚨 Prevent blocked users from logging in
            flash("Your account is blocked. Contact admin.", "danger")
            return redirect(url_for('login'))

        session['user_id'] = user.id  # Store user ID in session
        flash("Login successful!", "success")

        return redirect(url_for('admin_dashboard' if user.is_admin else 'dashboard'))

    return render_template("login.html")


@app.route('/admin')
@admin_required
def admin_dashboard():
    users = User.query.filter_by(is_admin=False).all()
    subjects = Subject.query.all()
    return render_template('admin_dashboard.html', users=users, subjects=subjects)

@app.route('/admin/block_user/<int:user_id>')
@admin_required
def block_user(user_id):
    user = User.query.get(user_id)
    if user and not user.is_admin:
        user.is_blocked = not user.is_blocked
        db.session.commit()
        flash(f"{'Blocked' if user.is_blocked else 'Unblocked'} user {user.username}.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add_subject', methods=['POST'])
@admin_required
def add_subject():
    name = request.form['name']
    description = request.form['description']
    qualification = request.form['qualification']
    subject = Subject(name=name, description=description, qualification=qualification)
    db.session.add(subject)
    db.session.commit()
    flash("Subject added successfully.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_subject/<int:subject_id>')
@admin_required
def delete_subject(subject_id):
    subject = Subject.query.get(subject_id)
    if subject:
        db.session.delete(subject)
        db.session.commit()
        flash("Subject deleted successfully.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add_chapter/<int:subject_id>', methods=['POST'])
@admin_required
def add_chapter(subject_id):
    name = request.form['name']
    description = request.form['description']
    chapter = Chapter(name=name, description=description, subject_id=subject_id)
    db.session.add(chapter)
    db.session.commit()
    flash("Chapter added successfully.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_chapter/<int:chapter_id>')
@admin_required
def delete_chapter(chapter_id):
    chapter = Chapter.query.get(chapter_id)
    if chapter:
        db.session.delete(chapter)
        db.session.commit()
        flash("Chapter deleted successfully.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add_quiz/<int:chapter_id>', methods=['POST'])
@admin_required
def add_quiz(chapter_id):
    duration = request.form['duration']
    quiz = Quiz(duration=duration, chapter_id=chapter_id)
    db.session.add(quiz)
    db.session.commit()
    flash("Quiz added successfully.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_quiz/<int:quiz_id>')
@admin_required
def delete_quiz(quiz_id):
    quiz = Quiz.query.get(quiz_id)
    if quiz:
        db.session.delete(quiz)
        db.session.commit()
        flash("Quiz deleted successfully.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add_question/<int:quiz_id>', methods=['POST'])
@admin_required
def add_question(quiz_id):
    question_statement = request.form['question_statement']
    option1 = request.form['option1']
    option2 = request.form['option2']
    option3 = request.form['option3']
    option4 = request.form['option4']
    correct_option = request.form['correct_option']
    correct_answer = request.form['correct_answer']
    question = Question(question_statement=question_statement, option1=option1, option2=option2,
                        option3=option3, option4=option4, correct_option=correct_option,
                        correct_answer=correct_answer, quiz_id=quiz_id)
    db.session.add(question)
    db.session.commit()
    flash("Question added successfully.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_question/<int:question_id>')
@admin_required
def delete_question(question_id):
    question = Question.query.get(question_id)
    if question:
        db.session.delete(question)
        db.session.commit()
        flash("Question deleted successfully.")
    return redirect(url_for('admin_dashboard'))

