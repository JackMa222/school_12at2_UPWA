from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3 as sql
import time
import random


def insertUser(username, password, DoB):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    
    hashed_password = generate_password_hash(password, method='scrypt')
    
    cur.execute(
        "INSERT INTO users (username,password,dateOfBirth) VALUES (?,?,?)",
        (username, hashed_password, DoB),
    )
    con.commit()
    con.close()

def retrieveUserId(username):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(f"SELECT id FROM users WHERE username = ?", (username, ))
    row = cur.fetchone()
    if row == None:
        con.close()
        return False
    return row[0]


def retrieveUsers(username, password):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(f"SELECT password FROM users WHERE username = ?", (username, ))
    row = cur.fetchone()
    con.close()
    
    dummy_hash = "scrypt:32768:8:1$ee2iRzbDj6WUq9DP$b4c8f9a3a366ea0f5b954131c62e9fb5d100ca9128ba05b178f4d0581401380c0f122f3cd4484ca76319c67a1dc262640d4e70ce88819652e9429632182b7354"
    
    if row:
        hashed_password = row[0]
        user_exists = True
    else:
        hashed_password = dummy_hash
        user_exists = False
    
    password_correct = check_password_hash(hashed_password, password)
    
    # Plain text log of visitor count as requested by Unsecure PWA management
    with open("visitor_log.txt", "r") as file:
        number = int(file.read().strip())
        number += 1
    with open("visitor_log.txt", "w") as file:
        file.write(str(number))

    return user_exists and password_correct


def insertFeedback(feedback):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(f"INSERT INTO feedback (feedback) VALUES (?)", (feedback, ))
    con.commit()
    con.close()


def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()
    return [row[1] for row in data]
