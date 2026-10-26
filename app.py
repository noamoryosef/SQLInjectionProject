
# import tools needed to run the website and access the database
import sqlite3
from flask import Flask, render_template, request, session, redirect

# create flask application
app = Flask(__name__)

# set a secret key to manage login sessions
app.secret_key = "development-only-secret-key"


# create a login page that is intentionally vulnerable to sql injection
@app.route("/vulnerable", methods=["GET", "POST"])
def vulnerable_login():

    # start with an empty message
    message = ""

    # check if someone submitted the login form
    if request.method == "POST":

        # read the username and password entered in the form
        username = request.form.get("username")
        password = request.form.get("password")

        # connect to the sqlite database
        connection = sqlite3.connect("users.db")
        cursor = connection.cursor()

        # intentionally insert user input directly into the sql query
        # this is unsafe because input can change the meaning of the query
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)

        # get the first matching account, if one exists
        user = cursor.fetchone()

        # close the database connection
        connection.close()

        # redirect to the dashboard if login succeeds
        if user:
            session["logged_in"] = True
            return redirect("/dashboard")
        else:
            message = "Invalid username or password."

    # display the login page
    return render_template("login.html", message=message)


# allow homepage to be opened (GET) and receive submitted login forms (POST)
@app.route("/", methods=["GET", "POST"])
def home():

    # start with an empty message
    message = ""

    # check if someone submitted the login form
    if request.method == "POST":

        # read username and password from the html form
        username = request.form.get("username")
        password = request.form.get("password")

        # connect to the sqlite database
        connection = sqlite3.connect("users.db")
        cursor = connection.cursor()

        # search for a user whose username and password match
        # the ? placeholders prevent sql injection
        cursor.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        )

        # get the first matching account, or none if no match exists
        user = cursor.fetchone()

        # close the database connection
        connection.close()

        # redirect to the dashboard if login succeeds
        if user:
            session["logged_in"] = True
            return redirect("/dashboard")
        else:
            message = "Invalid username or password."

    # display the login page and pass the result message to html
    return render_template("login.html", message=message)


# create a dashboard that can only be viewed after logging in
@app.route("/dashboard")
def dashboard():

    # redirect visitors who haven't logged in
    if not session.get("logged_in"):
        return redirect("/")

    # display the dashboard containing fictional user information
    return render_template("dashboard.html")


# allow users to log out and clear their session
@app.route("/logout")
def logout():

    # remove the login status from the session
    session.clear()

    # return to the login page
    return redirect("/")


# start the website when running this file
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)