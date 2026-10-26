# SQLInjectionProject

# to start the python backend, open terminal and paste:
python app.py

# (if database or users.db isn't updated, paste the following before trying again)
python database.py

# go to `ports` (to the right of `terminal`), hover over port 5000's forwarded address, click the browser icon to open the SECURE `login.html` in a new tab

# login credentials are...
# username:
admin
# password:
password

# to load the VULNERABLE login page, add the following to the opened URL:
/vulnerable

# on the VULNERABLE login page, enter this for the username:
' OR 1=1 --
# and for the password, LITERALLY ANYTHING (in sqlite it gets commented out so it doesn't matter what you type), you'll be taken to `dashboard.html`

# back in the terminal, do Ctrl+C to stop `app.py`