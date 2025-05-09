import re
import hashlib
import os
import sqlite3

# Connect to database
conn = sqlite3.connect("authenticate.db")
cursor = conn.cursor()

# create table
cursor.execute("""
    CREATE TABLE IF NOT EXISTS userdb (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
            users TEXT,
            pwd TEXT
    )
""")

print("Welcome to Asgard Key Vault 2!")

def create_account():
    username = ""
    password = ""

    while username == "":
        print("Before we get started, you need to create a username and password \
        to log into Asgard Key Vault 2.  Below are the rules for naming an account.\n")
        print("* Username must be between 5 and 32 characters")
        
        username = input("Please enter a username:")
        if 5 <= len(username) <= 32:
            print("Your username matched requirements")
        else:
            print("\nOpps! Your input didn't match the username rules\n")
            username = ""

    while password == "":
        
        print("* Must be between 5 and 32 characters")
        print("* Can contain numbers, upper and lowercase characters, and these symbols .!@$")
        print("* Must start with a number or upper/lowercase letter.\n")
        password= input("Please enter a password:")
        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.!@$]{4,31}$', password):
            salt = os.urandom(32)  # Generates a 32-byte random salt
            hashed_password = hashlib.pbkdf2_hmac(
                'sha256',                   # hashing algorithm
                password.encode('utf-8'),   # converts the password to bytes
                salt,
                200000                      # number of iterations
                )
        else:
            print("\nOpps! Your input didn't match the username rules\n")
            username = ""
            
    cursor.execute("INSERT INTO userdb (users, pwd) VALUES (?,?)", (username, hashed_password))

def authenticate():
    print("testing")

try:
    create_account()
    authenticate()

except FileNotFoundError:
    print("This is your first time logging into the mighty Asgard Key Vault 2!")
    create_account()
except Exception as e:
    print(f"An error occured: {e}")

