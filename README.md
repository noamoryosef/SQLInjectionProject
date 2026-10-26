# SQLInjectionProject

# how to start it, open terminal and paste:
python app.py

# (if database or users.db isn't updated, paste:)
python database.py

# go to `ports` (to the right of `terminal`), hover over port 5000's forwarded address, click the browser icon to open `login.html` in a new tab
# if all goes according to plan, SECURE login page loads

# ! to load the VULNERABLE login page, add the following to the opened URL:
/vulnerable

# on the VULNERABLE login page, enter this for the username:
' OR 1=1 --
# and for the password LITERALLY ANYTHING (in sqlite it gets commented out so it doesn't matter what you type), you'll get "Login Successful!"