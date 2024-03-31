import sqlite3
import hashlib
import secrets
import re
import getpass

class PasswordManager:
    def __init__(self, db_file='passwords.db'):
        """
        Initializes the PasswordManager class.

        Args:
            db_file (str): The path to the SQLite database file. Defaults to 'passwords.db'.
        """
        self.conn = sqlite3.connect(db_file)
        self.c = self.conn.cursor()
        self.create_table()

    def create_table(self):
        """
        Creates the 'passwords' table in the database if it doesn't exist.
        """
        self.c.execute('''CREATE TABLE IF NOT EXISTS passwords
                         (id INTEGER PRIMARY KEY, username TEXT, hash TEXT, salt TEXT)''')
        self.conn.commit()

    def add_user(self, username, password, confirm_password):
        """
        Adds a new user to the database with a username and password.

        Args:
            username (str): The username to be added.
            password (str): The password associated with the username.
            confirm_password (str): The confirmation of the password.

        Returns:
            bool: True if the user was successfully added, False otherwise.
        """
        if not (3 <= len(username) <= 15 and re.match("^[a-zA-Z0-9_!@#$%^&*()]+$", username)):
            print("The login must be from 3 to 15 characters and contain only alphanumeric characters and at least one special character !@#$%^&*().")
            return False

        if not (8 <= len(password) <= 25 and re.search("[!@#$%^&*()]+", password)):
            print("The password must be between 8 and 25 characters long and contain at least one special character !@#$%^&*().")
            return False

        if password != confirm_password:
            print("The passwords provided are not identical.")
            return False

        self.c.execute("SELECT * FROM passwords WHERE username=?", (username,))
        if self.c.fetchone():
            print("Username already exists.")
            return False

        if self.add_password(username, password):
            return True
        else:
            return False

    def generate_password_hash(self, password, salt=None):
        """
        Generates a hashed password and salt.

        Args:
            password (str): The password to be hashed.
            salt (bytes): Optional salt value. If not provided, a random salt will be generated.

        Returns:
            tuple: A tuple containing the hashed password and salt.
        """
        if not salt:
            salt = secrets.token_bytes(16)
        iterations = 100000

        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations).hex()

        return hashed_password, salt.hex()

    def add_password(self, username, password):
        """
        Adds a password to the database for a given username.

        Args:
            username (str): The username associated with the password.
            password (str): The password to be stored.

        Returns:
            bool: True if the password was successfully added, False otherwise.
        """
        try:
            hashed_password, salt = self.generate_password_hash(password)
            self.c.execute("INSERT INTO passwords (username, hash, salt) VALUES (?, ?, ?)", (username, hashed_password, salt))
            self.conn.commit()
            return True
        except Exception as e:
            print("Error:", e)
            self.conn.rollback()
            return False

    def verify_password(self, username, password):
        """
        Verifies a password for a given username.

        Args:
            username (str): The username to verify.
            password (str): The password to verify against the stored hash.

        Returns:
            bool: True if the password is correct, False otherwise.
        """
        self.c.execute("SELECT hash, salt FROM passwords WHERE username=?", (username,))
        result = self.c.fetchone()
        if result:
            hashed_password_stored, salt = result
            hashed_password_input, _ = self.generate_password_hash(password, bytes.fromhex(salt))
            return hashed_password_input == hashed_password_stored
        else:
            return False
