# Tyler Gibson
# CIS256
# Programming Assignment 5 (PA5)

from flask import Flask, request, render_template_string
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Route to display the login form
@app.route('/login', methods=['GET'])
def login_form():
    form_html = '''
    <form method="POST" action="/login">
        <label for="username">Username: </label>
        <input type="text" id="username" name="username">
        <label for="password">Password: </label>
        <input type="password" id="password" name="password">
        <input type="submit" value="Login">
    </form>
    '''
    return render_template_string(form_html)

# Route to handle form submission
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Input validation for username and password
    if not username or not password:
        return 'Both username and password are required!', 400

    # Validate username (only letters, numbers, and underscores)
    if not username.isalnum() and "_" not in username:
        return 'Username can only contain letters, numbers, and underscores!', 400

    # Validate password (at least 8 characters, must include letters and numbers)
    if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isalpha() for char in password):
        return 'Password must be at least 8 characters long and contain both letters and numbers!', 400

    # Hash the password using Flask-Bcrypt
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Process the login (for now, just displaying username and hashed password)
    return f'Username: {username}, Hashed Password: {hashed_password}'

if __name__ == '__main__':
    app.run(debug=True)