
import sqlite3
import hashlib

DATABASE = "users.db"


def create_database():
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT,
            password TEXT
        )
    """)

    # account for this security review.
    cursor.execute(
        "INSERT INTO users VALUES ('admin', ?)",
        (hashlib.md5(b"admin123").hexdigest(),)
    )

    connection.commit()
    connection.close()


def login(username, password):
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    # user input is inserted directly into SQL.
    query = (
        "SELECT * FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + hashlib.md5(password.encode()).hexdigest()
        + "'"
    )

    try:
        cursor.execute(query)
        user = cursor.fetchone()
        if user:
            print("Login successful")
        else:
            print("Invalid credentials")
    except sqlite3.Error as error:
        print("Database error:", error)
    finally:
        connection.close()


if __name__ == "__main__":
    create_database()
    username = input("Username: ")
    password = input("Password: ")
    login(username, password)
