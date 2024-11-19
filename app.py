import os
import sqlite3
import bleach
import re
from flask import Flask, render_template, request, Response, redirect, url_for, flash, session, send_from_directory, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta, timezone
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)

csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = 'trump123'



# brute force
limiter = Limiter(
    key_func=lambda: request.form.get('username', get_remote_address()),
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

lockout_until = datetime.now(timezone.utc) + timedelta(minutes=15)
failed_attempts = {}


# Configure the SQLite database
db_path = os.path.join(os.path.dirname(__file__), 'trump.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database
db = SQLAlchemy(app)

# Example Model (Table)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

# Function to run the SQL script if database doesn't exist
def initialize_database():
    if not os.path.exists('trump.db'):
        with sqlite3.connect('trump.db') as conn:
            cursor = conn.cursor()
            with open('trump.sql', 'r') as sql_file:
                sql_script = sql_file.read()
            cursor.executescript(sql_script)
            print("Database initialized with script.")

# Existing routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/quotes')
def quotes():
    return render_template('quotes.html')

@app.route('/sitemap')
def sitemap():
    return render_template('sitemap.html')
    
@app.route('/admin_panel')
def admin_panel():
    if 'user_role' in session and session['user_role'] == 'admin':
        return render_template('admin_panel.html')
    else:
        return "Unauthorized access", 403

# Route to handle redirects based on the destination query parameter
@app.route('/redirect', methods=['GET'])
def redirect_handler():
    destination = request.args.get('destination')

    if destination:
        return redirect(destination)
    else:
        return "Invalid destination", 400


@app.route('/comments', methods=['GET', 'POST'])
def comments():
    if request.method == 'POST':
        username = request.form['username']
        # Here we will be cleaning the user inout using Bleach Library
        # This will Sanitize the user input and take out any harmful code
        comment_text = bleach.clean(request.form['comment'])

        # Insert comment into the database
        insert_comment_query = text("INSERT INTO comments (username, text) VALUES (:username, :text)")
        db.session.execute(insert_comment_query, {'username': username, 'text': comment_text})
        db.session.commit()
        return redirect(url_for('comments'))

    # Retrieve all comments to display
    comments_query = text("SELECT username, text FROM comments")
    comments = db.session.execute(comments_query).fetchall()
    return render_template('comments.html', comments=comments)

@app.route('/download', methods=['GET'])
def download():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file_name = request.args.get('file', '')

    base_directory = os.path.join(os.path.dirname(__file__), 'docs')

    ALLOWED_FILES = {'lies.pdf', 'platinum-plan.pdf'}

    if file_name not in ALLOWED_FILES:
        return abort(403, "File not authorized!")

    try:
        return send_from_directory(base_directory, file_name, as_attachment=True)
    except FileNotFoundError:
        return "File not found", 404
    except PermissionError:
        return "Permission denied while accessing the file", 403

        
@app.route('/downloads', methods=['GET'])
def download_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('download.html')


@app.route('/profile/<int:user_id>', methods=['GET'])
def profile(user_id):
    if 'user_id' not in session or session['user_id'] != user_id:
        return "Unauthorized access to profile.", 403 

    query_user = text("SELECT * FROM users WHERE id = :user_id")
    user = db.session.execute(query_user, {'user_id': user_id}).fetchone()

    if user:
        query_cards = text("SELECT * FROM carddetail WHERE id = :user_id")
        cards = db.session.execute(query_cards, {'user_id': user_id}).fetchall()
        return render_template('profile.html', user=user, cards=cards)
    else:
        return "User not found.", 404


@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '')
    if not re.match(r"^[a-zA-Z0-9 ]*$", query):
        query = "Invalid input."
    return render_template('search.html', query=query)

@app.route('/forum')
def forum():
    return render_template('forum.html')

# Add login route
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"], error_message="Too many login attempts for this user. Try again later.")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check lockout for this username
        if username in failed_attempts:
            attempts, lockout_until = failed_attempts[username]
            if lockout_until and datetime.now(timezone.utc) < lockout_until:
                error = f'Account is locked. Try again at {lockout_until}.'
                return render_template('login.html', error=error)

        query = text("SELECT * FROM users WHERE username = :username")
        user = db.session.execute(query, {'username': username}).fetchone()

        if user and user.password == password:
            failed_attempts.pop(username, None)
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('profile', user_id=user.id))
        else:
            # Increment failed attempts
            attempts, lockout_until = failed_attempts.get(username, (0, None))
            attempts += 1
            lockout_until = datetime.now(timezone.utc) + timedelta(minutes=15) if attempts >= 5 else None
            failed_attempts[username] = (attempts, lockout_until)

            error = 'Invalid Credentials. Please try again.'
            if lockout_until:
                error += ' Too many failed attempts. Account locked for 15 minutes.'
            return render_template('login.html', error=error)

    return render_template('login.html')


# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove user session
    flash('You were successfully logged out', 'success')
    return redirect(url_for('index'))
    


if __name__ == '__main__':
    initialize_database()  # Initialize the database on application startup if it doesn't exist
    with app.app_context():
        db.create_all()  # Create tables based on models if they don't already exist
    app.run(debug=True)
