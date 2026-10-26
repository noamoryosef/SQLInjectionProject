
import sqlite3

# connect to a SQLite database called users.db (if it doesn't exist, SQLite automatically creates it)
connection = sqlite3.connect("users.db")

# create a cursor, which lets us send SQL commands to the database
cursor = connection.cursor()

# create a table to store user accounts (IF NOT EXISTS prevents an error if the table already exists)
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
""")

# add a fictional account for testing (? placeholders safely insert the values into the database)
cursor.execute("""
    INSERT OR IGNORE INTO users (username, password)
    VALUES (?, ?)
""", ("testuser", "password123"))

# save changes to the database
connection.commit()

# close the connection
connection.close()

print("Database initialized successfully!")