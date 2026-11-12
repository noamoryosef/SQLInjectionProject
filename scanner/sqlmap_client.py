# File Purpose: Handles communication with SQLmap and collects scan results.

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from the project's .env file.
load_dotenv()


# Retrieves the SQLmap installation path and verifies that it exists.
def get_sqlmap_path():
    sqlmap_path = os.getenv("SQLMAP_PATH")

    if not sqlmap_path:
        raise ValueError("SQLMAP_PATH is not configured in the .env file.")

    if not Path(sqlmap_path).is_file():
        raise FileNotFoundError("SQLmap file not found: " + sqlmap_path)

    return sqlmap_path