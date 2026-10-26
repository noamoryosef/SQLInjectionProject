
import sqlite3

# connect to the database, or create it if it doesn't exist
connection = sqlite3.connect("users.db")
cursor = connection.cursor()

# create a table for login accounts
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
""")

# create the single admin login account
cursor.execute("""
    INSERT OR IGNORE INTO users (username, password)
    VALUES (?, ?)
""", ("admin", "password"))

# create a separate table for fictional private information
cursor.execute("""
    CREATE TABLE IF NOT EXISTS customer_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
        account_balance REAL NOT NULL
    )
""")

# create 10 fictional customer records
customers = [
    ("Alex Carter", "alex@example.com", "555-0101", 1250.00),
    ("Jordan Smith", "jordan@example.com", "555-0102", 3400.50),
    ("Morgan Lee", "morgan@example.com", "555-0103", 875.25),
    ("Taylor Brooks", "taylor@example.com", "555-0104", 2175.80),
    ("Casey Morgan", "casey@example.com", "555-0105", 5620.00),
    ("Jamie Rivera", "jamie@example.com", "555-0106", 940.35),
    ("Riley Thompson", "riley@example.com", "555-0107", 3285.60),
    ("Sam Patel", "sam@example.com", "555-0108", 7410.25),
    ("Avery Wilson", "avery@example.com", "555-0109", 1680.90),
    ("Drew Anderson", "drew@example.com", "555-0110", 4950.75)
]

# clear old customer records so rerunning this script won't create duplicates
cursor.execute("DELETE FROM customer_records")

# insert the fictional records into the database
cursor.executemany("""
    INSERT INTO customer_records (name, email, phone, account_balance)
    VALUES (?, ?, ?, ?)
""", customers)

# save changes and close the database
connection.commit()
connection.close()

print("Database initialized successfully!")