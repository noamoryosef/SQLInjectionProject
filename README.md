
# SQL Injection Security Lab

A Flask-based web application designed to demonstrate and detect SQL injection vulnerabilities using SQLmap.

The application includes secure and intentionally vulnerable login pages, a protected dashboard containing fictional customer records, and an integrated SQL injection scanner.

SQLmap performs automated vulnerability testing through its REST API and the results are displayed directly on the website.

## 1. Requirements

Before running the project you need to have:

- Python installed
- Git installed
- SQLmap downloaded
- Project dependencies installed

Make sure when you download and extract SQLmap to a folder on your computer that you keep it separate from this projects directory.

## 2. Install Project Dependencies

Open a terminal in the SQLInjectionProject root directory and run:

```powershell
python -m pip install -r requirements.txt
```

## 3. Configure Environment Variables

Create a `.env` file in the project's root directory using `.env.example` as a reference.

Add the following settings:

```dotenv
SQLMAP_PATH=path/to/sqlmap.py
SQLMAP_API_URL=http://127.0.0.1:8775
SQLMAP_API_USERNAME=your_username
SQLMAP_API_PASSWORD=your_password
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-3.5-flash-lite
```

Replace the placeholders with your local SQLmap installation path and API credentials.
The Gemini key is used to generate a remediation report when SQLmap detects SQL injection.

**Important:** Never commit `.env` to GitHub. Give each collaborator only the credentials they need through a private channel.

## 4. Initialize the Database

If this is your first time running the project, or the database needs to be reset, run:

```powershell
python database.py
```

This initializes the SQLite database used by the application.

## 5. Start the Flask Application

In the project directory, run:

```powershell
python app.py
```

The Flask application runs at:

http://127.0.0.1:8000

Keep this terminal running.

## 6. Start the SQLmap API Server

Open a second terminal and navigate to the folder where you extracted SQLmap.

For example:

```powershell
cd C:\Tools\sqlmap-master
```

Start the SQLmap API server:

```powershell
python sqlmapapi.py -s -H 127.0.0.1 -p 8775 --username YOUR_USERNAME --password YOUR_PASSWORD
```

Replace `YOUR_USERNAME` and `YOUR_PASSWORD` with the credentials configured in your `.env` file.

Keep this terminal running while using the scanner.

The SQLmap API listens locally on port `8775`.

**Important:** Keep the API bound to `127.0.0.1` and do not share any secret tokens displayed when the server starts.

## 7. Login Pages

The application provides two login endpoints:

| Page | URL |
|---|---|
| Secure Login | http://127.0.0.1:8000/ |
| Vulnerable Login | http://127.0.0.1:8000/vulnerable |

### Login Credentials

For normal authentication:

- **Username:** `admin`
- **Password:** `password`

### SQL Injection Demonstration

On the intentionally vulnerable login page, enter:

**Username:**

```text
' OR 1=1 --
```

**Password:** Any nonempty value.

This demonstrates how an improperly constructed SQL query may allow authentication bypass.

The secure login page is designed to reject SQL injection attempts.

## 8. Run the SQL Injection Scanner

1. Make sure both Flask and the SQLmap API server are running.
2. Open http://127.0.0.1:8000/scanner in your browser.
3. Click **Security Scanner** 
4. Click **Run Security Scan**.
5. Wait for SQLmap to finish testing both login pages.
6. Review the findings displayed on the results page.

The scanner automatically tests the `username` parameter on both the secure and vulnerable login endpoints.

### Scan Results

The results page displays:

- Number of login pages scanned
- Number of vulnerable parameters
- Number of detected SQL injection techniques
- Detection status for each login page
- Affected parameters and database information
- Descriptions of the detected SQL injection techniques

SQLmap's results are retrieved through its REST API and formatted by the Python application.

A scan with no detected vulnerabilities does not guarantee that the application is completely secure.

## 9. Troubleshooting

### Flask Application Does Not Start

Make sure the dependencies are installed and the database has been initialized.

### SQLmap API Connection Fails

Verify that the SQLmap API server is running on port `8775` and that the credentials in `.env` match those used to start the server.

### Scanner Displays an Error Page

Check the Flask and SQLmap API terminals for error messages.

Restart the SQLmap API server if necessary.

### Scanner Takes a Long Time

SQLmap performs multiple injection tests.

The website displays a loading indicator while scanning.

The current integration has a 180-second timeout per scan.

## 10. Stop the Application

To stop the Flask application, press `Ctrl + C` in its terminal.

To stop the SQLmap API server, press `Ctrl + C` in its terminal.

## Project Scope

This project is intended for educational cybersecurity testing.

SQLmap is configured to scan only the two predefined local login endpoints.

Do not use the scanner against websites or systems without explicit authorization.
