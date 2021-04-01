"""
Name: Ben Sutter
Date: November 6th, 2020
Class: SDEV 300
Purpose: Adds a password reset page, a failed login attempt log, and further password complexity.
"""

import string
from datetime import datetime
from flask import Flask, render_template, flash, request, redirect, url_for, session
from passlib.hash import sha256_crypt


def get_current_time():
    """Grabs current date and time"""
    return datetime.now().strftime("%B %d, %Y %H:%M")


def complexity_check(password):
    """Checks to make sure the password meets the complexity requirements"""
    # Booleans to keep track of which requirements have been met
    has_special = False
    has_upper = False
    has_lower = False
    has_digit = False
    # Runs through each character of the password passed as a parameter
    # If a char is special, a number, lowercase, or uppercase than change respective boolean to true
    for char in password:
        if char in string.punctuation:
            has_special = True
        elif char in string.ascii_uppercase:
            has_upper = True
        elif char in string.ascii_lowercase:
            has_lower = True
        elif char in string.digits:
            has_digit = True
    # Return true if all four booleans are true and the length of the password > 11
    if len(password) > 11 and has_special and has_upper and has_lower and has_digit:
        return True
    return False


def is_registered(username):
    """Checks to see if the user has already registered (their name is in the file)"""
    with open('passfile') as file:
        for line in file:
            # If the username is found in the passfile, then True, it is registered.
            if username == line.strip():
                return True
    return False


def registration_check(username, password):
    """Performs various checks, if all checks are passed then write username and pass to file"""
    if is_registered(username):
        return "User already registered"
    if not complexity_check(password):
        return "Password must be at least 12 characters in length, include at least " \
               "1 uppercase character, \n1 lowercase character, 1 number and 1 special character."
    # If user is not registered and password is complex, add username and (hashed) password to file.
    with open('passfile', "a") as file:
        file.writelines(username + "\n")
        file.writelines(sha256_crypt.hash(password) + "\n")
    return "Registration successful!"


def login_match(username, password):
    """Checks to see if the user is registered, if registered then pull their encrypted password
    Then check to make sure the encrypted password matches the incoming password"""
    if is_registered(username):
        # If user is registered, then check entered password against the user's hashed password.
        if sha256_crypt.verify(password, retrieve_password(username)):
            return True
    return False


# Creates a list of common passwords from the common password file
common_passwords = []
common_file = open('CommonPassword.txt', 'r')
# Adds each line to the list as a separate string
for common_pass in common_file:
    common_passwords.append(common_pass.strip())


def common_password_check(password):
    """Compares each common password against the incoming password.
    If a match is found, flash the common password to notify what value is too common"""
    # Keeps track of if a secret is found in the password.
    is_common = False
    for _, item in enumerate(common_passwords):
        # If a matching value is found (regardless of case) flash the secret.
        if item.upper() in password.upper():
            # If the item is a number, don't say anything about case insensitivity
            if item.isdigit():
                flash("'" + item + "' is too common in passwords, "
                                   "please make a new one without it.")
            else:
                flash("'" + item + "' (case-insensitive) is too common in passwords, "
                                   "please make a new one without it.")
            # Because this isn't return true, it can flash multiple common secrets.
            is_common = True  # If any secrets are found, the password is common
    # False if no secrets were found, true if any were.
    return is_common


def find_password_line(username):
    """Returns the line of a password when given a username.
    This function is used in retrieve_password and reset_password"""
    password_line = 0  # Keeps track of what line the file is currently reading
    with open('passfile') as file:
        for line in file:
            # Since 0 corresponds to line 1 (first username) then by adding one we get the password
            password_line += 1
            # If the username is found in the passfile, then break to stop close file
            if username == line.strip():
                break
    # Return the line where the password line is.
    return password_line


def retrieve_password(username):
    """A very simple function that when given a username will retrieve the associated hash password.
    It opens the file, grabs the password string and strips it of any white space."""
    return open('passfile').readlines()[find_password_line(username)].strip()


def reset_password(username, current_password, new_password):
    """Utilizes various functions to reset the user's password if their login is successful."""
    if (login_match(username, current_password) and complexity_check(new_password)
            and not common_password_check(new_password)):
        # Copies the contents of passfile so the user's password can be reset
        old_passfile = open("passfile", "r").readlines()
        # Changes the line where the user's password is to the new password they entered
        old_passfile[find_password_line(username)] = sha256_crypt.hash(new_password) + "\n"
        # Opens the password file for overwriting
        password_file = open("passfile", "w")
        # Overwrites the file with the new passfile (changed user's password)
        password_file.writelines(old_passfile)
        # Close the reader
        password_file.close()
        # Notify user of successful update
        flash("Password successfully updated!")
        return True
    # If user is not registered, notify user
    if not login_match(username, current_password):
        flash("Current password is incorrect!")
    # If the username does not match the password, notify user
    elif not is_registered(username):
        flash("Account with that username not found!")
    # If new password is not complex, notify user
    elif not complexity_check(new_password):
        flash("New password is not complex enough!")
    return False


app = Flask(__name__)


@app.route("/", methods=["POST", "GET"])
def login():
    """Creates the login page from login.html, there are two forms (username and password)
    for the user to fill out. Unless they successfully login, the only other page they can access
    is the registration page. Various flashes will be displayed upon unsuccessful login attempts."""
    if request.method == "POST":
        # uname comes from the username input field, psw comes from password field.
        uname = request.form["uname"]
        psw = request.form["psw"]
        if login_match(uname, psw):
            flash("Login successful!")  # Flashes on home page to notify successful login
            session["user"] = uname  # Successful log in means the user can access the other pages
            return redirect(url_for("home"))  # Redirect to the home page.
        if not is_registered(uname):
            flash("User not found, check input for spelling errors, "
                  "or register by clicking the button below.")
        elif not login_match(uname, psw):
            with open('log', "a") as log_file:
                # Adds failed login attempt to login log file
                log_file.writelines("\nFailed login attempt for " + uname + " from IP Address: "
                                    + request.remote_addr + "| Date/time: " + get_current_time())
            flash("Incorrect password, please check input and try again.")
    return render_template("login.html")  # Shows login page on first load and failed logins.


@app.route("/reset", methods=["POST", "GET"])
def reset():
    """Creates the password reset page so an existing user can update their password."""
    if request.method == "POST":
        uname = request.form["uname"]  # Comes from the username input field
        current_psw = request.form["current_psw"]  # Comes from the current password input field
        new_psw = request.form["new_psw"]  # Comes from the new password input field
        if reset_password(uname, current_psw, new_psw):
            # Redirect to login page, flash already happens in method
            return redirect(url_for("login"))
    return render_template("reset.html")  # Shows reset page on first load and failed reset attempts


@app.route("/registration", methods=["POST", "GET"])
def registration():
    """Creates the home page based on home.html, current_time is passed for use in html"""
    if request.method == "POST":
        # Grabs values after form submission at registration page and assigns them to variables
        uname = request.form["uname"]
        psw = request.form["psw"]
        confirm_psw = request.form["confirm_psw"]
        # If user is not registered, both passwords match, and password is complex then register
        if not is_registered(uname) and psw == confirm_psw and psw != uname \
                and complexity_check(psw):
            # Flashes Registration successful! and adds username and password to passfile.
            flash(registration_check(uname, psw))
            return redirect(url_for("login"))  # Redirect to login page.
        # If the password fields don't match, notify the user.
        if psw != confirm_psw:
            flash("The passwords don't match!")
        # If username is the same as password, notify user.
        elif psw == uname:
            flash("Your password can't be your username!")
        # If passwords match, flash message from registration_check (user registered or not complex)
        else:
            flash(registration_check(uname, psw))
    return render_template("registration.html")  # Loads page and reloads on failed registration.


@app.route("/home")
def home():
    """Creates the home page based on home.html, current_time is passed for use in html"""
    # If the user is not logged in, notify the user and redirect to the login page.
    if "user" not in session:
        flash("You must login to access the home page!")
        return redirect(url_for("login"))
    return render_template("home.html", current_time=get_current_time())


@app.route('/page2')
def page2():
    """Creates the second page based on page2.html, current_time is passed for use in html"""
    # If the user is not logged in, notify the user and redirect to the login page.
    if "user" not in session:
        flash("You must login to access the second page!")
        return redirect(url_for("login"))
    return render_template("page2.html", current_time=get_current_time())


@app.route('/page3')
def page3():
    """Creates the third page based on page3.html, current_time is passed for use in html"""
    # If the user is not logged in, notify the user and redirect to the login page.
    if "user" not in session:
        flash("You must login to access the third page!")
        return redirect(url_for("login"))
    return render_template("page3.html", current_time=get_current_time())


# Launches the website
if __name__ == "__main__":
    app.secret_key = 'top secret key'
    app.run()
