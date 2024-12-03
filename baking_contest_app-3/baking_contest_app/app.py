"""
Name: Jamal Bryan
Date: 11/24/2024
Assignment: Module 13: Send Encrypted Message
Due Date: 11/24/2024
About this project:
Solve a simple programming problem based on various approaches to computer security and information management.
Build a small scale real-world application that incorporates the principles of secure computing including cryptography,
network security, and data protection
Assumptions:
The application creates the database upon execution.
There are 6 initial users created however there are no contest entries created when the application spins up
In order to create new users you must be signed in to a user with the highest security level (3)
The application if you change the application keys you must ensure they work with application. It must be 16 bytes
The create_baking_contest_db.py script has to be run first.
All work below was performed by Jamal Bryan
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import socket
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import base64

app = Flask(__name__)
app.secret_key = 'CEN4521'

# Fixed AES key (16 bytes, must be consistent)
SECRET_KEY = b"myverysecurekeyy"  # Ensure this key is exactly 16 bytes

# Encrypt data using AES in ECB mode
def encrypt_data(data):
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    padded_data = pad(data.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted).decode()

# Decrypt data using AES in ECB mode
def decrypt_data(data):
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(data))
    return unpad(decrypted, AES.block_size).decode()

# Database connection setup
def connect_db():
    return sqlite3.connect("baking_contest.db")


# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Encrypt username and password for lookup
        encrypted_username = encrypt_data(username)
        encrypted_password = encrypt_data(password)

        conn = connect_db()
        cur = conn.cursor()
        cur.execute("SELECT UserId, Name, SecurityLevel FROM BakingContestPeople WHERE Name = ? AND LoginPassword = ?",
                    (encrypted_username, encrypted_password))
        user = cur.fetchone()
        conn.close()

        if user:
            session['user_id'] = user[0]
            session['username'] = decrypt_data(user[1])  # Decrypt for display
            session['security_level'] = user[2]
            return redirect(url_for('home'))
        else:
            flash("Invalid username and/or password!")
            return redirect(url_for('login'))

    return render_template("login.html")


# Logout Route
@app.route('/logout')
def logout():
    session.clear()  # Clear the session
    flash("You have been logged out.")
    return redirect(url_for('login'))


# Home Page Route
@app.route('/')
def home():
    if 'username' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))

    # Pass user data and access options to the template
    return render_template("home.html", username=session['username'], security_level=session['security_level'])


## Add New User Route
@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if 'security_level' not in session or session['security_level'] != 3:
        flash("You do not have permission to access this page.")
        return redirect(url_for('home'))

    if request.method == 'POST':
        name = request.form['name']
        age = request.form['age']
        phone = request.form['phone']
        password = request.form['password']
        security_level = request.form['security_level']

        # Validation checks
        errors = []

        # Check if name is empty or contains spaces
        if not name.strip():
            errors.append("Name cannot be empty.")
        elif " " in name:
            errors.append("Name cannot contain spaces.")

        # Check if age is valid
        if not age.isdigit() or not (0 < int(age) < 121):
            errors.append("Age must be a whole number between 1 and 120.")

        # Check if phone is empty or contains spaces
        if not phone.strip():
            errors.append("Phone number cannot be empty.")
        elif " " in phone:
            errors.append("Phone number cannot contain spaces.")

        # Check if security level is valid
        if not security_level.isdigit() or not (1 <= int(security_level) <= 3):
            errors.append("Security Level must be between 1 and 3.")

        # Check if password is empty or contains spaces
        if not password.strip():
            errors.append("Password cannot be empty.")
        elif " " in password:
            errors.append("Password cannot contain spaces.")

        # If there are errors, display them without submitting the form
        if errors:
            return render_template("results.html", msg="; ".join(errors))

        # Encrypt fields before inserting
        encrypted_name = encrypt_data(name)
        encrypted_phone = encrypt_data(phone)
        encrypted_password = encrypt_data(password)

        conn = connect_db()
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO BakingContestPeople (Name, Age, PhNum, SecurityLevel, LoginPassword)
            VALUES (?, ?, ?, ?, ?)
        ''', (encrypted_name, age, encrypted_phone, security_level, encrypted_password))
        conn.commit()
        conn.close()

        flash("New user added successfully.")
        return redirect(url_for('home'))

    return render_template("add_user.html")


# List Users Route
@app.route('/list_users')
def list_users():
    if 'security_level' not in session or session['security_level'] not in [2, 3]:
        flash("You do not have permission to access this page.")
        return redirect(url_for('home'))

    conn = connect_db()
    cur = conn.cursor()
    cur.execute("SELECT UserId, Name, Age, PhNum, SecurityLevel, LoginPassword FROM BakingContestPeople")
    rows = cur.fetchall()
    conn.close()

    users = []
    for row in rows:
        try:
            # Decrypt fields and add to the users list
            users.append({
                'UserId': row[0],
                'Name': decrypt_data(row[1]),
                'Age': row[2],
                'PhNum': decrypt_data(row[3]),
                'SecurityLevel': row[4],
                'LoginPassword': decrypt_data(row[5])
            })
        except ValueError as e:
            # Handle decryption errors (e.g., invalid/corrupted data)
            flash(f"Error decrypting data for UserId {row[0]}: {e}")
            continue
    print(f"users:{users}")
    return render_template("list_users.html", users=users)


# My Contest Entry Results Route
@app.route('/my_results')
def my_results():
    if 'user_id' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))

    # Fetch contest entries for the logged-in user
    conn = connect_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT NameOfBakingItem, NumExcellentVotes, NumOkVotes, NumBadVotes FROM BakingContestEntry WHERE UserId = ?",
        (session['user_id'],))
    results = cur.fetchall()
    conn.close()

    return render_template("my_results.html", results=results, username=session['username'])


# Add a Contest Entry Route
@app.route('/add_entry', methods=['GET', 'POST'])
def add_entry():
    if 'user_id' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        name_of_baking_item = request.form['name_of_baking_item']

        # Validation: NameOfBakingItem must not be empty or only spaces
        if not name_of_baking_item.strip():
            return render_template("results.html", msg="Name of baking item cannot be empty.")

        # Add entry to the database
        try:
            conn = connect_db()
            cur = conn.cursor()
            cur.execute('''
                INSERT INTO BakingContestEntry (UserId, NameOfBakingItem, NumExcellentVotes, NumOkVotes, NumBadVotes)
                VALUES (?, ?, ?, ?, ?)
            ''', (session['user_id'], name_of_baking_item, 0, 0, 0))  # Initialize votes to 0
            conn.commit()
            conn.close()
            return render_template("results.html", msg="Contest entry successfully added.")
        except Exception as e:
            return render_template("results.html", msg=f"Error adding entry: {e}")

    return render_template("add_entry.html")

# List All Contest Results (only for SecurityLevel 3)
@app.route('/contest_results')
def contest_results():
    if 'security_level' not in session or session['security_level'] != 3:
        flash("You do not have permission to access this page.")
        return redirect(url_for('home'))

    conn = connect_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT BakingContestEntry.EntryId, BakingContestEntry.UserId, BakingContestPeople.Name, 
               BakingContestEntry.NameOfBakingItem, BakingContestEntry.NumExcellentVotes, 
               BakingContestEntry.NumOkVotes, BakingContestEntry.NumBadVotes
        FROM BakingContestEntry
        JOIN BakingContestPeople ON BakingContestEntry.UserId = BakingContestPeople.UserId
    ''')
    results = cur.fetchall()
    conn.close()
    return render_template("contest_results.html", results=results)

# Submit a Baking Contest Entry Vote Page
@app.route('/submit_vote', methods=['GET', 'POST'])
def submit_vote():
    if 'security_level' not in session or session['security_level'] < 2:
        flash("You do not have permission to access this page.")
        return redirect(url_for('home'))

    if request.method == 'POST':
        entry_id = request.form['entry_id']
        excellent_votes = request.form['excellent_votes']
        ok_votes = request.form['ok_votes']
        bad_votes = request.form['bad_votes']

        # Validate input
        errors = []
        if not entry_id.isdigit() or int(entry_id) <= 0:
            errors.append("EntryId must be a numeric value > 0.")
        if not excellent_votes.isdigit() or int(excellent_votes) < 0:
            errors.append("Number of Excellent Votes must be >= 0.")
        if not ok_votes.isdigit() or int(ok_votes) < 0:
            errors.append("Number of Ok Votes must be >= 0.")
        if not bad_votes.isdigit() or int(bad_votes) < 0:
            errors.append("Number of Bad Votes must be >= 0.")

        # Check if EntryId exists in the database
        conn = connect_db()
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM BakingContestEntry WHERE EntryId = ?", (entry_id,))
        entry_exists = cur.fetchone()
        conn.close()
        if not entry_exists:
            errors.append("EntryId does not exist in the database.")

        if errors:
            return render_template("results.html", msg="; ".join(errors))

        # Create and send message
        try:
            message = f"{entry_id}^%${excellent_votes}^%${ok_votes}^%${bad_votes}"
            encrypted_message = encrypt_data(message)

            # Send message to the server and receive response
            with socket.create_connection(("localhost", 9999)) as sock:
                sock.sendall(encrypted_message.encode())
                response = sock.recv(1024).decode()  # Receive response from the server

            return render_template("results.html", msg=response)
        except Exception as e:
            return render_template("results.html", msg=f"Error - Vote NOT sent: {e}")

    return render_template("submit_vote.html")


# Main Method
if __name__ == '__main__':
    app.run(debug=True)
