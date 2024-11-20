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


class User(db.Model):
    '''
    Represents a user in the database with a unique username and password.
    '''
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'


def initialize_database():
    '''
    This function checks if the 'trump.db' database file exists. 
    If not, it creates the database by executing the SQL commands 
    from the 'trump.sql' file, which sets up the required tables 
    and initial data. Once completed, it prints a confirmation message.
    '''

    if not os.path.exists('trump.db'):
        with sqlite3.connect('trump.db') as conn:
            cursor = conn.cursor()
            with open('trump.sql', 'r') as sql_file:
                sql_script = sql_file.read()
            cursor.executescript(sql_script)
            print("Database initialized with script.")


@app.route('/')
def index():
    '''
    Renders the homepage of the website.
    '''

    return render_template('index.html')


@app.route('/quotes')
def quotes():
    '''
    Renders the quotes page of the website.
    '''

    return render_template('quotes.html')


@app.route('/sitemap')
def sitemap():
    '''
    Renders the sitemap page of the website.
    '''

    return render_template('sitemap.html')


@app.route('/admin_panel')
def admin_panel():
    '''
    Renders the admin panel page if the user has an 'admin' role.
    Returns a 403 error message for unauthorized access.
    '''

    if 'user_role' in session and session['user_role'] == 'admin':
        return render_template('admin_panel.html')
    else:
        return "Unauthorized access", 403


@app.route('/redirect', methods=['GET'])
def redirect_handler():
    '''
    Handles redirects based on the specified destination parameter.
    Only allows redirection to predefined routes listed in `allowed_routes`.
    Returns a 403 error for unauthorized redirect attempts.
    '''

    destination = request.args.get('destination', '')

    allowed_routes = ["index", "quotes", "search", "comments", "login", "sitemap", "downloads"]

    if destination in allowed_routes:
        return redirect(url_for(destination))
    else:
        return abort(403, "Unauthorized redirect attempt!")


@app.route('/comments', methods=['GET', 'POST'])
def comments():
    '''
    Handles displaying and adding comments for the website.

    - For GET requests:
        Retrieves all comments from the database and displays them on the comments page.

    - For POST requests:
        1. Accepts user input for `username` and `comment` from the form.
        2. Sanitizes the comment input using the Bleach library to prevent harmful content.
        3. Inserts the sanitized comment and username into the database.
        4. Redirects back to the comments page after successfully adding the comment.
    '''

    if request.method == 'POST':
        username = request.form['username']
        comment_text = bleach.clean(request.form['comment'])

        insert_comment_query = text("INSERT INTO comments (username, text) VALUES (:username, :text)")
        db.session.execute(insert_comment_query, {'username': username, 'text': comment_text})
        db.session.commit()
        return redirect(url_for('comments'))

    comments_query = text("SELECT username, text FROM comments")
    comments = db.session.execute(comments_query).fetchall()

    return render_template('comments.html', comments=comments)


@app.route('/download', methods=['GET'])
def download():
    '''
    Handles secure file downloads for authenticated users.

    - Verifies if the user is logged in by checking the `user_id` in the session.
      If not logged in, redirects to the login page.

    - Retrieves the `file` parameter from the query string.

    - Ensures the requested file is within the list of allowed files 
      (`lies.pdf` and `platinum-plan.pdf`). If the file is not authorized, 
      returns a 403 error.

    - Uses `send_from_directory` to securely serve files from the `docs` folder.

    - Handles errors:
        - Returns a 404 error if the file is not found.
        - Returns a 403 error if there are permission issues accessing the file.

    This ensures that only authenticated users can download specific allowed files
    securely, mitigating vulnerabilities like path traversal attacks.
    '''

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


@app.route('/downloads', methods=['GET'], endpoint='downloads')
def download_page():
    '''
    Renders the download page for authenticated users.

    - Checks if the user is logged in by verifying the presence of `user_id` in the session.
      If the user is not logged in, redirects them to the login page.

    - If the user is authenticated, serves the `download.html` template,
      which provides access to the file download options.

    This ensures that only logged-in users can access the download page, 
    preventing unauthorized access.
    '''

    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('download.html')


@app.route('/profile/<int:user_id>', methods=['GET'])
def profile(user_id):
    '''
    Displays the profile page for a specific user.

    - Ensures the user is authenticated by checking if `user_id` exists in the session 
      and matches the requested `user_id`. If not, it returns an "Unauthorized access" error.

    - Retrieves the user details from the `users` table using the provided `user_id`.

    - If the user exists, retrieves related card details from the `carddetail` table 
      and renders the `profile.html` template, passing the user and card information.

    - If the user does not exist, returns a "User not found" error with a 404 status code.

    This function ensures secure access to user profiles while maintaining data integrity.
    '''

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
    '''
    Handles the search functionality for the website.

    - Retrieves the search query from the request arguments. Defaults to an empty string if no query is provided.

    - Validates the search query using a regular expression to ensure it contains only alphanumeric characters 
      and spaces. If the validation fails, the query is replaced with "Invalid input."

    - Renders the `search.html` template, passing the sanitized or default query as a parameter.

    This function prevents malicious input by limiting the query to safe characters, protecting the application 
    from injection attacks.
    '''

    query = request.args.get('query', '')

    if not re.match(r"^[a-zA-Z0-9 ]*$", query):
        query = "Invalid input."

    return render_template('search.html', query=query)


# @app.route('/forum')
# def forum():
#     '''
#     Renders the forum page of the website. But we dont have it.
#     '''
#     return render_template('forum.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"], error_message="Too many login attempts for this user. Try again later.")
def login():
    '''
    Handles user login functionality.

    - For POST requests:
        - Retrieves the username and password from the submitted form.
        - Checks if the username has been locked out due to multiple failed login attempts. If locked, the user 
          receives an error message with the lockout expiration time.
        - Validates the provided credentials against the database.
        - If credentials are valid:
            - Clears any failed attempts for the username.
            - Sets the user's session with their ID.
            - Redirects the user to their profile page.
        - If credentials are invalid:
            - Increments the failed attempt count for the username.
            - Locks the account for 15 minutes if there are 5 or more failed attempts.
            - Returns an error message indicating invalid credentials or account lockout.

    - For GET requests:
        - Renders the `login.html` template to display the login form.

    This function incorporates rate limiting and account lockout mechanisms to mitigate brute force attacks, 
    enhancing login security.
    '''

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


@app.route('/logout')
def logout():
    '''
    Logs out the current user by removing their session data.

    - Deletes the 'user_id' from the session to effectively log out the user.
    - Displays a success message indicating the user was logged out.
    - Redirects the user to the homepage (index).

    This function ensures that no sensitive session data remains after a user logs out.
    '''

    session.pop('user_id', None)
    flash('You were successfully logged out', 'success')

    return redirect(url_for('index'))


if __name__ == '__main__':
    initialize_database() 
    with app.app_context():
        db.create_all()
    app.run(debug=True)
