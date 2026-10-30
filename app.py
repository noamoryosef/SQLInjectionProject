
# import tools needed to run the website and access the database
import sqlite3
from scanner.scanner import run_scan
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



# display the admin dashboard after a successful login
@app.route("/dashboard")
def dashboard():

    # prevent visitors from viewing records without logging in
    if not session.get("logged_in"):
        return redirect("/")

    # connect to the database
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    # retrieve all fictional customer records
    cursor.execute("""
        SELECT name, email, phone, account_balance
        FROM customer_records
    """)

    customers = cursor.fetchall()

    # close the database connection
    connection.close()

    # send the customer records to the html page
    return render_template("dashboard.html", customers=customers)


# allow users to log out and clear their session
@app.route("/logout")
def logout():

    # remove the login status from the session
    session.clear()

    # return to the login page
    return redirect("/")

# Displays the security scanner page.
@app.route("/scanner")
def scanner_page():
    return render_template("scanner.html")

# Runs the SQL injection scanner when requested from the website.
@app.route("/run-scan", methods=["POST"])
def run_security_scan():

    # Run the scanner and collect its results.
    baseline_access, baseline_results, all_results = run_scan()

    # Count the total number of payload tests.
    total_tests = len(all_results)

    # Count how many payload tests detected a potential vulnerability.
    positive_results = sum(
        1 for result in all_results if result["vulnerability_detected"]
    )

    # Count unique URLs where potential vulnerabilities were detected.
    vulnerable_urls = {
        result["url"]
        for result in all_results
        if result["vulnerability_detected"]
    }

    vulnerable_pages = len(vulnerable_urls)

    # Display the scan results on a webpage.
    return render_template(
        "scanner_results.html",
        baseline_access=baseline_access,
        baseline_results=baseline_results,
        all_results=all_results,
        total_tests=total_tests,
        positive_results=positive_results,
        vulnerable_pages=vulnerable_pages
    )

# start the website when running this file
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)