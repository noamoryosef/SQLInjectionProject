# import tools needed to run the website
from flask import Flask, render_template, request

# create flask application
app = Flask(__name__)


# allow homepage to be opened (GET) and receive submitted login forms (POST)
@app.route("/", methods=["GET", "POST"])
def home():

    # check if someone clicked the Log In button
    if request.method == "POST":

        # read username and password from HTML form
        username = request.form.get("username")
        password = request.form.get("password")

        # for now, just check that Flask received the information (don't display the actual password)
        print("Username:", username)
        print("Password received:", bool(password))

    # display login page
    return render_template("login.html")


# start the website when running this file
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)