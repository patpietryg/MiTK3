import sqlite3
import hashlib
import secrets
import re


def add_user():
    while True:
        login = input("Enter your login: ")
        if not (3 <= len(login) <= 15 and re.match("^[a-zA-Z0-9_!@#$%^&*()]+$", login)):
            print("The login must be from 3 to 15 characters and contain only alphanumeric characters and at least one special character !@#$%^&*().")
            continue

        password = input("Enter your password: ")
        if not (8 <= len(password) <= 25 and re.search("[!@#$%^&*()]+", password)):
            print("The password must be between 8 and 25 characters long and contain at least one special character !@#$%^&*().")
            continue

        confirm_password = input("Confirm password: ")
        if password != confirm_password:
            print("The passwords provided are not identical.")
            continue

        break

    #dodanie do bazy

