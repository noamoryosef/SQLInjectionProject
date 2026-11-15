# SQLInjectionProject

# Configure Gemini on each developer's machine:
# Copy .env.example to .env and set GEMINI_API_KEY to the shared project key.
# The local .env is ignored by Git; do not commit credentials.

# to start the python backend, open terminal and paste:
python app.py

# Open /scanner while the app is running and run a scan. Positive findings
# are sent to Gemini and its remediation report appears below the scan results.
# Without GEMINI_API_KEY, scan results still appear with a configuration message.

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
