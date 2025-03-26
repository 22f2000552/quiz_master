from flask import render_template, request, redirect, url_for, flash, session
from app import app
from werkzeug.security import  generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
from models import *
from sqlalchemy.sql import func
from pytz import timezone, utc

def auth_required(func):
    @wraps(func)
    def inner(*args,**kwargs):
        if 'user_id' in session:
            return (func(*args,**kwargs))
        else:
            flash("Please login to continue")
            return redirect(url_for('login'))
    return inner   

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
        cpassword = request.form['cpassword']
        dob = request.form['dob']
        qualification = request.form.get('qualification', 'Not Provided')  # Default value if missing

        # Convert dob to datetime object
        dob_date = datetime.strptime(dob, '%Y-%m-%d')

        # Check if email or username already exists
        existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
        if existing_user:
            flash("Email or username already exists. Try again!", "danger")
            return redirect(url_for('signup'))

        if password != cpassword:
            flash("Passwords do not match. Try again!", "danger")
            return redirect(url_for('signup'))
        
        # Hash the password
        hashed_password = generate_password_hash(password)

        # Create new user
        new_user = User(name=name, email=email, username=username, passhash=hashed_password, dob=dob_date, qualification=qualification)
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully! You can now login.", "success")
        return redirect(url_for('login'))
    return render_template('signup.html')



# @app.route('/dashboard')
# def dashboard():
#     if 'user_id' not in session:
#         return redirect(url_for('login'))  # Redirect if not logged in

#     user = User.query.get(session['user_id'])  # Fetch logged-in user
#     return render_template('dashboard.html', user=user)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        flash("Please log in to access the dashboard.", "danger")
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])  # Fetch the logged-in user
    scores = db.session.query(
        Score,
        Quiz,
        Chapter,
        Subject
    ).join(Quiz, Score.quiz_id == Quiz.id)\
     .join(Chapter, Quiz.chapter_id == Chapter.id)\
     .join(Subject, Chapter.subject_id == Subject.id)\
     .filter(Score.user_id == user.id).all()

    # Pre-calculate percentages for each score
    processed_scores = []
    ist = timezone('Asia/Kolkata')  # Define IST timezone
    for score, quiz, chapter, subject in scores:
        percentage = (score.total_scored / quiz.total_marks) * 100 if quiz.total_marks else 0
        timestamp_ist = score.timestamp.replace(tzinfo=utc).astimezone(ist)
        processed_scores.append((score, quiz, chapter, subject, round(percentage, 2), timestamp_ist))
    
    if request.method == 'POST':
        # Update user details
        user.name = request.form['name']
        user.username = request.form['username']
        user.qualification = request.form['qualification']
        user.dob = datetime.strptime(request.form['dob'], '%Y-%m-%d')
        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('dashboard.html', user=user, scores=processed_scores)

# @app.route('/admin')
# @auth_required
# def admin():
#     user = User.query.get(session.get('user_id'))  # Use .get() to avoid KeyError
#     if not user or not user.is_admin:  # Prevent NoneType error
#         flash("Access denied. Admins only.")
#         return redirect(url_for('index'))
#     return render_template("admin_dashboard.html", user=user)

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
        session['is_admin'] = user.is_admin
        flash("Login successful!", "success")

        return redirect(url_for('admin_dashboard' if user.is_admin else 'dashboard'))

    return render_template("login.html")


@app.route('/admin')
@auth_required
def admin_dashboard():
    user = User.query.get(session.get('user_id'))  # Use .get() to avoid KeyError
    if not user or not user.is_admin:  # Prevent NoneType error
        flash("Access denied. Admins only.")
        return redirect(url_for('index'))
    users = User.query.filter_by(is_admin=False).all()
    subjects = Subject.query.all()

    return render_template('admin_dashboard.html', users=users, subjects=subjects)

@app.route('/admin/block_unblock/<int:user_id>', methods=['POST'])
def block_unblock_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_blocked = not user.is_blocked
    db.session.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/add_subject', methods=['POST'])
def add_subject():
    name = request.form.get('name')
    description = request.form.get('description')

    if name and description:
        new_subject = Subject(name=name, description=description)
        db.session.add(new_subject)
        db.session.commit()
        flash('Subject added successfully!', 'success')

    return redirect(url_for('admin_dashboard'))

@app.route('/delete_subject/<int:subject_id>', methods=['POST'])
def delete_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    db.session.delete(subject)
    db.session.commit()
    flash('Subject deleted successfully!', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/edit_subject/<int:subject_id>', methods=['GET', 'POST'])
def edit_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)

    if request.method == 'POST':
        subject.name = request.form['name']
        subject.description = request.form['description']
        db.session.commit()
        flash("Subject updated successfully!", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_subject.html', subject=subject)


@app.route('/view_chapters/<int:subject_id>')
def view_chapters(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    chapters = Chapter.query.filter_by(subject_id=subject_id).all()
    return render_template('view_chapters.html', subject=subject, chapters=chapters)

@app.route('/add_chapter/<int:subject_id>', methods=['POST'])
def add_chapter(subject_id):
    name = request.form.get('name')
    description = request.form.get('description')

    if name and description:
        new_chapter = Chapter(name=name, description=description, subject_id=subject_id)
        db.session.add(new_chapter)
        db.session.commit()
        flash('Chapter added successfully!', 'success')

    return redirect(url_for('view_chapters', subject_id=subject_id))

@app.route('/delete_chapter/<int:chapter_id>', methods=['POST'])
def delete_chapter(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    subject_id = chapter.subject_id
    db.session.delete(chapter)
    db.session.commit()
    flash('Chapter deleted successfully!', 'danger')
    return redirect(url_for('view_chapters', subject_id=subject_id))

@app.route('/edit_chapter/<int:chapter_id>', methods=['GET', 'POST'])
def edit_chapter(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)

    if request.method == 'POST':
        # Update chapter details
        chapter.name = request.form['name']
        chapter.description = request.form['description']

        db.session.commit()
        flash("Chapter updated successfully!", "success")

        return redirect(url_for('view_chapters', subject_id=chapter.subject_id))

    # Render edit form
    return render_template('edit_chapter.html', chapter=chapter)


@app.route('/admin/chapters/<int:chapter_id>/quizzes')
def view_quizzes(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    quizzes = Quiz.query.filter_by(chapter_id=chapter.id).all()
    subject = chapter.subject  # Assuming Chapter has a relationship with Subject

    for quiz in quizzes:
        quiz.total_marks = db.session.query(func.sum(Question.marks)).filter_by(quiz_id=quiz.id).scalar() or 0

    return render_template('view_quizzes.html', chapter=chapter, quizzes=quizzes,subject=subject)

@app.route('/admin/chapters/<int:chapter_id>/quizzes/add', methods=['POST'])
def add_quiz(chapter_id):
    date = request.form.get('date')
    duration = request.form.get('duration')
    
    if not duration:
        flash("Duration is required", "danger")
        return redirect(url_for('view_quizzes', chapter_id=chapter_id))
    
    quiz_date = datetime.strptime(date, "%Y-%m-%d") if date else None

    new_quiz = Quiz(date=quiz_date, duration=int(duration), chapter_id=chapter_id)
    db.session.add(new_quiz)
    db.session.commit()
    flash("Quiz added successfully!", "success")
    return redirect(url_for('view_quizzes', chapter_id=chapter_id))

@app.route('/admin/chapters/<int:chapter_id>/quizzes/<int:quiz_id>/delete', methods=['POST'])
def delete_quiz(chapter_id, quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    db.session.delete(quiz)
    db.session.commit()
    flash("Quiz deleted successfully!", "success")
    return redirect(url_for('view_quizzes', chapter_id=chapter_id))
@app.route('/quiz/<int:quiz_id>/questions', methods=['GET', 'POST'])

# @app.route('/admin/chapters/<int:chapter_id>/quizzes/<int:quiz_id>/edit', methods=['GET', 'POST'])
# def edit_quiz(chapter_id, quiz_id):
#     quiz = Quiz.query.get_or_404(quiz_id)

#     if request.method == 'POST':
#         # Retrieve updated data from the form
#         date = request.form.get('date')
#         duration = request.form.get('duration')

#         # Validate and update the quiz
#         quiz.date = datetime.strptime(date, "%Y-%m-%d") if date else quiz.date
#         quiz.duration = int(duration) if duration else quiz.duration

#         db.session.commit()
#         flash("Quiz updated successfully!", "success")
#         return redirect(url_for('view_quizzes', chapter_id=chapter_id))

#     return render_template('edit_quiz.html', quiz=quiz, chapter_id=chapter_id)


@app.route('/quiz/<int:quiz_id>/questions', methods=['GET', 'POST'])
def view_questions(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    chapter = quiz.chapter  # Assuming Quiz has a relationship with Chapter
    subject = chapter.subject  # Assuming Chapter has a relationship with Subject
    questions = Question.query.filter_by(quiz_id=quiz_id).all()

    if request.method == 'POST':
        question_statement = request.form['question_statement']
        option1 = request.form['option1']
        option2 = request.form['option2']
        option3 = request.form['option3']
        option4 = request.form['option4']
        correct_option = int(request.form['correct_option'])
        marks = int(request.form['marks'])

        correct_answer = [option1, option2, option3, option4][correct_option - 1]

        new_question = Question(
            question_statement=question_statement,
            option1=option1,
            option2=option2,
            option3=option3,
            option4=option4,
            correct_option=correct_option,
            correct_answer=correct_answer,
            marks=marks,
            quiz_id=quiz_id
        )

        db.session.add(new_question)

        # Update total marks in quiz
        quiz.total_marks += marks
        db.session.commit()
        
        flash('Question added successfully!', 'success')
        return redirect(url_for('view_questions', quiz_id=quiz_id))

    return render_template('view_questions.html', quiz=quiz, chapter=chapter, subject=subject, questions=questions)

@app.route('/quiz/<int:quiz_id>/delete_question/<int:question_id>', methods=['POST'])
def delete_question(quiz_id, question_id):
    question = Question.query.get_or_404(question_id)
    db.session.delete(question)
    db.session.commit()
    flash("Question deleted successfully!", "success")
    return redirect(url_for('view_questions', quiz_id=quiz_id))

@app.route('/quiz/<int:quiz_id>/question/<int:question_id>/edit', methods=['GET', 'POST'])
def edit_question(quiz_id, question_id):
    question = Question.query.get_or_404(question_id)

    if request.method == 'POST':
        question.question_statement = request.form['question_statement']
        question.option1 = request.form['option1']
        question.option2 = request.form['option2']
        question.option3 = request.form['option3']
        question.option4 = request.form['option4']
        question.marks = request.form['marks']
        question.correct_option = int(request.form['correct_option'])
        question.correct_answer = [question.option1, question.option2, question.option3, question.option4][question.correct_option - 1]
        
        db.session.commit()
        flash('Question updated successfully!', 'success')

        return redirect(url_for('view_questions', quiz_id=question.quiz_id))  # ✅ Fetching quiz_id from question

    return render_template('edit_question.html', question=question)

@app.route('/quiz')
def quiz_home():
    subjects = Subject.query.all()  # Fetch all subjects
    return render_template('quiz_home.html', subjects=subjects)

@app.route('/quiz/subject/<int:subject_id>')
def quiz_chapters(subject_id):
    subject = Subject.query.get_or_404(subject_id)  # Get subject by ID
    chapters = Chapter.query.filter_by(subject_id=subject_id).all()  # Fetch chapters of the subject
    return render_template('quiz_chapters.html', subject=subject, chapters=chapters)

@app.route('/quiz/chapter/<int:chapter_id>')
def quiz_quizzes(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)  # Get chapter by ID
    quizzes = Quiz.query.filter_by(chapter_id=chapter_id).all()  # Fetch quizzes of the chapter
    subject = chapter.subject
    return render_template('quiz_quizzes.html', chapter=chapter, quizzes=quizzes,subject=subject)




@app.route('/quiz/<int:quiz_id>/start', methods=['GET', 'POST'])
def start_quiz(quiz_id):
    if 'user_id' not in session:
        flash("Please log in to take the quiz.", "danger")
        return redirect(url_for('login'))

    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()

    # Initialize the quiz start time and end time in the session
    if 'quiz_start_time' not in session:
        session['quiz_start_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        session['quiz_end_time'] = (datetime.now() + timedelta(minutes=quiz.duration)).strftime('%Y-%m-%d %H:%M:%S')

    # Check if the quiz time has expired
    quiz_end_time = datetime.strptime(session['quiz_end_time'], '%Y-%m-%d %H:%M:%S')
    if datetime.now() > quiz_end_time:
        flash("Time is up! Your quiz has been automatically submitted.", "warning")
        return submit_quiz(quiz_id, questions,quiz)

    if request.method == 'POST':
        return submit_quiz(quiz_id, questions,quiz)

    # Calculate remaining time
    remaining_time = (quiz_end_time - datetime.now()).seconds

    return render_template('quiz.html', quiz=quiz, questions=questions, remaining_time=remaining_time)


def submit_quiz(quiz_id, questions,quiz):
    """Handles quiz submission and score calculation."""
    total_score = 0
    for question in questions:
        selected_option = request.form.get(f'question_{question.id}')
        if selected_option and int(selected_option) == question.correct_option:
            total_score += question.marks

    # Save the score to the database
    scores = Score( total_scored=total_score, quiz_id=quiz_id, user_id=session['user_id'] )
    db.session.add(scores)
    db.session.commit()

    

    # Clear quiz session data
    session.pop('quiz_start_time', None)
    session.pop('quiz_end_time', None)
    # flash("You have been logged out after submitting the quiz. login to your dashboard to see your score.", "info")
    # return redirect(url_for('login'))
    flash("Quiz submitted successfully! Check your dashboard for the score.", "success")
    return redirect(url_for('dashboard'))  # Redirect to dashboard instead of login