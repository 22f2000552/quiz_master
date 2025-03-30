from flask import render_template, request, redirect, url_for, flash, session
from app import app
from werkzeug.security import  generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
from models import *
from sqlalchemy.sql import func
from pytz import timezone, utc
from sqlalchemy import or_

def auth_required(func):
    @wraps(func)
    def inner(*args,**kwargs):
        if 'user_id' in session:
            return (func(*args,**kwargs))
        else:
            flash("Please login to continue")
            return redirect(url_for('login'))
    return inner   


@app.route("/logout")
def logout():
    session.pop("user_id", None)  
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
        qualification = request.form.get('qualification', 'Not Provided') 

        
        dob_date = datetime.strptime(dob, '%Y-%m-%d')

        
        existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
        if existing_user:
            flash("Email or username already exists. Try again!", "danger")
            return redirect(url_for('signup'))

        if password != cpassword:
            flash("Passwords do not match. Try again!", "danger")
            return redirect(url_for('signup'))
        
        
        hashed_password = generate_password_hash(password)

       
        new_user = User(name=name, email=email, username=username, passhash=hashed_password, dob=dob_date, qualification=qualification)
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully! You can now login.", "success")
        return redirect(url_for('login'))
    return render_template('signup.html')



# @app.route('/dashboard', methods=['GET', 'POST'])
# def dashboard():
#     if 'user_id' not in session:
#         flash("Please log in to access the dashboard.", "danger")
#         return redirect(url_for('login'))
    
#     user = User.query.get(session['user_id'])  # Fetch the logged-in user
#     subjects = Subject.query.all()
#     subject_names = []
#     total_quizzes = []

#     for subject in subjects:
#         quiz_count = db.session.query(Quiz).join(Chapter).filter(Chapter.subject_id == subject.id).count()
#         subject_names.append(subject.name)
#         total_quizzes.append(quiz_count)
#         # subject_quiz_data.append((subject, total_quizzes))
#     scores = db.session.query(
#         Score,
#         Quiz,
#         Chapter,
#         Subject
#     ).join(Quiz, Score.quiz_id == Quiz.id)\
#      .join(Chapter, Quiz.chapter_id == Chapter.id)\
#      .join(Subject, Chapter.subject_id == Subject.id)\
#      .filter(Score.user_id == user.id).all()

#     # Pre-calculate percentages for each score
#     processed_scores = []
#     ist = timezone('Asia/Kolkata')  # Define IST timezone
#     for score, quiz, chapter, subject in scores:
#         percentage = (score.total_scored / quiz.total_marks) * 100 if quiz.total_marks else 0
#         timestamp_ist = score.timestamp.replace(tzinfo=utc).astimezone(ist)
#         processed_scores.append((score, quiz, chapter, subject, round(percentage, 2), timestamp_ist))
    
#     if request.method == 'POST':
#         # Update user details
#         user.name = request.form['name']
#         user.username = request.form['username']
#         user.qualification = request.form['qualification']
#         user.dob = datetime.strptime(request.form['dob'], '%Y-%m-%d')
#         db.session.commit()
#         flash("Profile updated successfully!", "success")
#         return redirect(url_for('dashboard'))

#     return render_template('dashboard.html', user=user, scores=processed_scores,subject_names=subject_names, total_quizzes=total_quizzes)


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        flash("Please log in to access the dashboard.", "danger")
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])  
    subjects = Subject.query.all()

    
    subject_names = []
    total_quizzes = []
    
    
    attempted_subjects = []
    attempted_quizzes = []
    attempt_count = {}

    for subject in subjects:
        quiz_count = db.session.query(Quiz).join(Chapter).filter(Chapter.subject_id == subject.id).count()
        subject_names.append(subject.name)
        total_quizzes.append(quiz_count)

   
    scores = db.session.query(
        Score, Quiz, Chapter, Subject
    ).join(Quiz, Score.quiz_id == Quiz.id)\
     .join(Chapter, Quiz.chapter_id == Chapter.id)\
     .join(Subject, Chapter.subject_id == Subject.id)\
     .filter(Score.user_id == user.id).all()
    
        
    processed_scores = []
    ist = timezone('Asia/Kolkata') 
    for score, quiz, chapter, subject in scores:
        percentage = (score.total_scored / quiz.total_marks) * 100 if quiz.total_marks else 0
        timestamp_ist = score.timestamp.replace(tzinfo=utc).astimezone(ist)
        processed_scores.append((score, quiz, chapter, subject, round(percentage, 2), timestamp_ist))

    for _, quiz, _, subject in scores:
        if subject.name in attempt_count:
            attempt_count[subject.name] += 1
        else:
            attempt_count[subject.name] = 1

    for subject, count in attempt_count.items():
        attempted_subjects.append(subject)
        attempted_quizzes.append(count)

    return render_template(
        'dashboard.html', 
        user=user, 
        subject_names=subject_names, 
        total_quizzes=total_quizzes, 
        scores=processed_scores,
        attempted_subjects=attempted_subjects, 
        attempted_quizzes=attempted_quizzes
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.passhash, password):
            flash("Invalid email or password", "danger")
            return redirect(url_for('login'))

        if user.is_blocked:  
            flash("Your account is blocked. Contact admin.", "danger")
            return redirect(url_for('login'))

        session['user_id'] = user.id 
        session['is_admin'] = user.is_admin
        flash("Login successful!", "success")

        return redirect(url_for('admin_dashboard' if user.is_admin else 'dashboard'))

    return render_template("login.html")


@app.route('/admin')
@auth_required
def admin_dashboard():
    user = User.query.get(session.get('user_id')) 
    if not user or not user.is_admin: 
        flash("Access denied. Admins only.")
        return redirect(url_for('index'))
    users = User.query.filter_by(is_admin=False).all()
    subjects = Subject.query.all()

   
    subject_names = []
    quiz_attempt_counts = []

    for subject in subjects:
        user_count = db.session.query(Score.user_id).join(Quiz).join(Chapter).filter(Chapter.subject_id == subject.id).distinct().count()
        subject_names.append(subject.name)
        quiz_attempt_counts.append(user_count)

   
    search_results = []
    search_type = request.args.get('parameter')
    query = request.args.get('query', '').strip()

    if search_type and query:
        if search_type == "user":
            search_results = User.query.filter(
                or_(User.email.ilike(f"%{query}%"), User.name.ilike(f"%{query}%"))
            ).all()

        elif search_type == "subject":
            search_results = Subject.query.filter(Subject.name.ilike(f"%{query}%")).all()

        elif search_type == "quizzes":
            search_results = db.session.query(Quiz, Chapter, Subject)\
                .join(Chapter, Quiz.chapter_id == Chapter.id)\
                .join(Subject, Chapter.subject_id == Subject.id)\
                .filter(or_(Quiz.id.ilike(f"%{query}%"), Chapter.name.ilike(f"%{query}%"), Subject.name.ilike(f"%{query}%")))\
                .all()

    return render_template(
        'admin_dashboard.html',
        users=users,
        subjects=subjects,
        subject_names=subject_names,
        quiz_attempt_counts=quiz_attempt_counts,
        search_results=search_results,
        search_type=search_type,
        query=query
    )

    
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
       
        chapter.name = request.form['name']
        chapter.description = request.form['description']

        db.session.commit()
        flash("Chapter updated successfully!", "success")

        return redirect(url_for('view_chapters', subject_id=chapter.subject_id))

   
    return render_template('edit_chapter.html', chapter=chapter)


@app.route('/edit_quiz/<int:quiz_id>', methods=['GET', 'POST'])
def edit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    chapter = quiz.chapter

    if request.method == 'POST':
        date = request.form.get('date')
        duration = request.form.get('duration')

        if date:
            quiz.date = datetime.strptime(date, "%Y-%m-%d")
        if duration:
            quiz.duration = int(duration)

        db.session.commit()
        flash("Quiz updated successfully!", "success")
        return redirect(url_for('view_quizzes', chapter_id=quiz.chapter_id,))

    return render_template('edit_quiz.html', quiz=quiz, chapter_id=chapter.id)

@app.route('/admin/chapters/<int:chapter_id>/quizzes')
def view_quizzes(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    quizzes = Quiz.query.filter_by(chapter_id=chapter.id).all()
    subject = chapter.subject  

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
    chapter = quiz.chapter  
    subject = chapter.subject 
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

        return redirect(url_for('view_questions', quiz_id=question.quiz_id)) 
    return render_template('edit_question.html', question=question)

@app.route('/quiz')
def quiz_home():
    subjects = Subject.query.all()  
    return render_template('quiz_home.html', subjects=subjects)

@app.route('/quiz/subject/<int:subject_id>')
def quiz_chapters(subject_id):
    subject = Subject.query.get_or_404(subject_id) 
    chapters = Chapter.query.filter_by(subject_id=subject_id).all() 
    return render_template('quiz_chapters.html', subject=subject, chapters=chapters)

@app.route('/quiz/chapter/<int:chapter_id>')
def quiz_quizzes(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    quizzes = Quiz.query.filter_by(chapter_id=chapter_id).all()  
    subject = chapter.subject
    return render_template('quiz_quizzes.html', chapter=chapter, quizzes=quizzes,subject=subject)




@app.route('/quiz/<int:quiz_id>/start', methods=['GET', 'POST'])
def start_quiz(quiz_id):
    if 'user_id' not in session:
        flash("Please log in to take the quiz.", "danger")
        return redirect(url_for('login'))

    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()

   
    if 'quiz_start_time' not in session:
        session['quiz_start_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        session['quiz_end_time'] = (datetime.now() + timedelta(minutes=quiz.duration)).strftime('%Y-%m-%d %H:%M:%S')

    
    quiz_end_time = datetime.strptime(session['quiz_end_time'], '%Y-%m-%d %H:%M:%S')
    if datetime.now() > quiz_end_time:
        flash("Time is up! Your quiz has been automatically submitted.", "warning")
        return submit_quiz(quiz_id, questions,quiz)

    if request.method == 'POST':
        return submit_quiz(quiz_id, questions,quiz)

    remaining_time = (quiz_end_time - datetime.now()).seconds

    return render_template('quiz.html', quiz=quiz, questions=questions, remaining_time=remaining_time)


def submit_quiz(quiz_id, questions,quiz):
    """Handles quiz submission and score calculation."""
    total_score = 0
    for question in questions:
        selected_option = request.form.get(f'question_{question.id}')
        if selected_option and int(selected_option) == question.correct_option:
            total_score += question.marks

  
    scores = Score( total_scored=total_score, quiz_id=quiz_id, user_id=session['user_id'] )
    db.session.add(scores)
    db.session.commit()

    

   
    session.pop('quiz_start_time', None)
    session.pop('quiz_end_time', None)
   
    flash("Quiz submitted successfully! Check your dashboard for the score.", "success")
    return redirect(url_for('dashboard'))  

# @app.route('/user_summary')
# def user_summary():
#     user = session.get('user_id')
    
#     scores = db.session.query(
#         Score,
#         Quiz,
#         Chapter,
#         Subject
#     ).join(Quiz, Score.quiz_id == Quiz.id)\
#      .join(Chapter, Quiz.chapter_id == Chapter.id)\
#      .join(Subject, Chapter.subject_id == Subject.id)\
#      .filter(Score.user_id == user).all()
#     return render_template('user_sum.html')

@app.route('/user_summary')
def user_summary():
    # Ensure the user is logged in
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to view your summary.", "danger")
        return redirect(url_for('login'))

    # Fetch the user
    user = User.query.get_or_404(user_id)

    # Prepare data for charts
    subject_names = []
    total_quizzes = []
    attempted_subjects = []
    attempted_quizzes = []

    # Fetch all subjects
    subjects = Subject.query.all()
    for subject in subjects:
        # Total quizzes for each subject
        total_quiz_count = db.session.query(Quiz).join(Chapter)\
            .filter(Chapter.subject_id == subject.id).count()
        subject_names.append(subject.name)
        total_quizzes.append(total_quiz_count)

        # Attempted quizzes for each subject
        attempted_quiz_count = db.session.query(Score.quiz_id).join(Quiz).join(Chapter)\
            .filter(Chapter.subject_id == subject.id, Score.user_id == user.id).distinct().count()
        attempted_subjects.append(subject.name)
        attempted_quizzes.append(attempted_quiz_count)

    return render_template(
        'user_sum.html',
        subject_names=subject_names,
        total_quizzes=total_quizzes,
        attempted_subjects=attempted_subjects,
        attempted_quizzes=attempted_quizzes
    )

@app.route('/view_user/<int:user_id>')
@auth_required
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('view_user.html', user=user)