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
    cur.execute(f"SELECT * FROM users WHERE username = ?", (username, ))
    if cur.fetchone() == None:
        con.close()
        return False
    else:
        cur.execute(f"SELECT password FROM users WHERE username = ?", (username, ))
        row = cur.fetchone()
        con.close()
        # Plain text log of visitor count as requested by Unsecure PWA management
        with open("visitor_log.txt", "r") as file:
            number = int(file.read().strip())
            number += 1
        with open("visitor_log.txt", "w") as file:
            file.write(str(number))
        # Simulate response time of heavy app for testing purposes
        time.sleep(random.randint(80, 90) / 1000)
        if row:
            hashed_password = row[0]
            return check_password_hash(hashed_password, password)
        return False


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
