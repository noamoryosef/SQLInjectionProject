
# import tools needed to run the website and access the database
import sqlite3
from flask import Flask, render_template, request

# create flask application
app = Flask(__name__)


# create a separate login page that is intentionally vulnerable to sql injection
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

        # display whether the login succeeded or failed
        if user:
            message = "Login successful!"
        else:
            message = "Invalid username or password."

    # display the same login page
    return render_template("login.html", message=message)


# allow homepage to be opened (GET) and receive submitted login forms (POST)
@app.route("/", methods=["GET", "POST"])
def home():

    # start with an empty message to display on the page
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
        # the ? placeholders keep user input separate from the sql command
        cursor.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        )

        # get the first matching account, or none if no match exists
        user = cursor.fetchone()

        # close the database connection
        connection.close()

        # check whether a matching account was found
        if user:
            message = "Login successful!"
        else:
            message = "Invalid username or password."

    # display the login page and pass the result message to html
    return render_template("login.html", message=message)


# start the website when running this file
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)