
import sqlite3
import hashlib
import hmac
import secrets
import getpass
from pathlib import Path

DATABASE = Path(__file__).with_name("secure_users.db")
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SALT_SIZE = 16
KEY_SIZE = 32


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(SALT_SIZE)

    password_hash = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=KEY_SIZE,
    )
    return salt.hex(), password_hash.hex()


def verify_password(password, salt_hex, hash_hex):
    try:
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(hash_hex)
    except ValueError:
        return False

    actual_hash = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=len(expected_hash),
    )
    return hmac.compare_digest(actual_hash, expected_hash)


def connect():
    return sqlite3.connect(DATABASE)


def create_database():
    with connect() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY COLLATE NOCASE,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)


def register_user(username, password):
    username = username.strip()

    if not username or len(username) > 64:
        print("Username must contain 1–64 characters.")
        return False

    if len(password) < 12:
        print("Password must be at least 12 characters.")
        return False

    salt, password_hash = hash_password(password)

    try:
        with connect() as connection:
            connection.execute(
                "INSERT INTO users (username, salt, password_hash) "
                "VALUES (?, ?, ?)",
                (username, salt, password_hash),
            )
        print("Account created successfully.")
        return True
    except sqlite3.IntegrityError:
        print("Unable to create account with those details.")
        return False


def login(username, password):
    with connect() as connection:
        row = connection.execute(
            "SELECT salt, password_hash FROM users WHERE username = ?",
            (username.strip(),),
        ).fetchone()

    if row and verify_password(password, row[0], row[1]):
        print("Login successful.")
        return True

    print("Invalid username or password.")
    return False


def main():
    create_database()
    print("Local Secure Login Demo")
    print("1. Register")
    print("2. Log in")

    choice = input("Choose an option: ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    if choice == "1":
        register_user(username, password)
    elif choice == "2":
        login(username, password)
    else:
        print("Invalid option.")


if __name__ == "__main__":
    main()
