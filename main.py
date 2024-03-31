import sqlite3
import hashlib
import secrets
import re
import getpass

conn = sqlite3.connect('passwords.db')
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS passwords
             (id INTEGER PRIMARY KEY, username TEXT, hash TEXT, salt TEXT)''')

def add_user():
    while True:
        login = input("Enter your login: ")
        if not (3 <= len(login) <= 15 and re.match("^[a-zA-Z0-9_!@#$%^&*()]+$", login)):
            print("The login must be from 3 to 15 characters and contain only alphanumeric characters and at least one special character !@#$%^&*().")
            continue

        password = getpass.getpass(prompt='Enter your password: ')
        if not (8 <= len(password) <= 25 and re.search("[!@#$%^&*()]+", password)):
            print("The password must be between 8 and 25 characters long and contain at least one special character !@#$%^&*().")
            continue

        confirm_password = getpass.getpass(prompt='Confirm password: ')
        if password != confirm_password:
            print("The passwords provided are not identical.")
            continue

        break

    if add_password(login, password):
        print("Success!")
    else:
        print("Fail ")

def generate_password_hash(password, salt=None):
    if not salt:
        salt = secrets.token_bytes(16)
    iterations = 100000

    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations).hex()

    return hashed_password, salt.hex()

def add_password(username, password):
    try:
        hashed_password, salt = generate_password_hash(password)
        c.execute("INSERT INTO passwords (username, hash, salt) VALUES (?, ?, ?)", (username, hashed_password, salt))
        conn.commit()
        return True
    except Exception as e:
        print("Error:", e)
        conn.rollback()
        return False

def verify_password(username, password):
    c.execute("SELECT hash, salt FROM passwords WHERE username=?", (username,))
    result = c.fetchone()
    if result:
        hashed_password_stored, salt = result
        hashed_password_input, _ = generate_password_hash(password, bytes.fromhex(salt))
        return hashed_password_input == hashed_password_stored
    else:
        return False


print(verify_password("Adam", "mocnehaslo@"))
