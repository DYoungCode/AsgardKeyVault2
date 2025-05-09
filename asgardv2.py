import re
import hashlib
import os
import sqlite3
import sys

auth_database = "authenticate.db"
# Connect to database
conn = sqlite3.connect(auth_database)
cursor = conn.cursor()

# create database used to store authentication to AsgardKeyVault2
cursor.execute("""
    CREATE TABLE IF NOT EXISTS userdb (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
            users TEXT UNIQUE,
            pwd BLOB,
            salt BLOB
    )
""")

def check_db_for_users():
    cursor.execute("SELECT COUNT(*) FROM userdb")
    result = cursor.fetchone()
    row_count = result[0]
    return row_count

def menu():
    print("(L)ogin")
    print("(C)reate new account")
    print("(Q)uit")
    response = input("What would you like to do? Please enter a command: ")
    if response.upper() == "L":
        
        row_exists = authenticate() 
        print("Row Exists:", row_exists)
        if row_exists == True:
            print("Login successful!")
        else:
            print("Invalid credentials. Please try again.")
            authenticate()
    elif response.upper() == "C":
        create_account()
    elif response.upper() == "Q":
        sys.exit()
    else:
        print("That wasn't one of the choices, please try again.")
        menu

def authenticate():

    username = input('Please enter your username:')
    password = input('Please enter your password:')

    cursor.execute("SELECT pwd, salt FROM userdb where users = ?", (username,))
    row = cursor.fetchone()
    if row is None:
        return False   # User not found
    
    stored_hash = row[0]
    stored_salt = row[1]

    if isinstance(stored_salt, str):
        stored_salt = bytes.fromhex(stored_salt)

    test_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        stored_salt,
        200000
    )
    
    return test_hash == stored_hash



# This function checks to see if the user already exists in the database
def check_user_exists(username):
    cursor.execute("SELECT 1 FROM userdb WHERE users = ?", (username,))
    result = cursor.fetchone()
    return result


# this function creates an account if one doesn't already exist with that name
# if the name exists the while loop repeats
def create_account():
    username = ""
    password = ""

    while username == "":
        print("* Username must be between 5 and 32 characters")
        
        username = input("Please enter a username:")
        if 5 <= len(username) <= 32:
            
            #Check to see if username exists, if they don't exist repeat while loop
            user_exists = check_user_exists(username)
            if user_exists is None:
                print("Username set to", username, "\n")
            else:
                # Change output to different color font 
                print("\n *** Username already exists, try again ***\n")
                username = ""
                
        else:
            print("\nOpps! Your input didn't match the username length rules\n")
            username = ""

    while password == "":
        
        print("Password Rules:")
        print("* Must be between 5 and 32 characters")
        print("* Can contain numbers, upper and lowercase characters, and these symbols .!@$")
        print("* Must start with a number or upper/lowercase letter.\n")
        password= input("Please enter a password: ")
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
            password = ""
            
    cursor.execute("INSERT INTO userdb (users, pwd, salt) VALUES (?,?,?)", (username, hashed_password, salt))
    conn.commit()

print("Welcome to Asgard Key Vault 2!")

if check_db_for_users():
    menu()  
else:
    print("Before we get started, you need to create a username and password \
          to log into Asgard Key Vault 2.  Below are the rules for naming an account.\n")
    create_account()


