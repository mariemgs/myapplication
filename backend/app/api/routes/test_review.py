# This file has intentional issues for testing the AI code review agent

import os
import subprocess
from fastapi import APIRouter

router = APIRouter()

# BAD: hardcoded secret
SECRET_KEY = "mysecretkey123"
DB_PASSWORD = "admin123"

# BAD: SQL injection vulnerability
def get_user(user_id: str):
    query = "SELECT * FROM users WHERE id = " + user_id  # SQL injection
    return query

# BAD: O(n²) complexity
def find_duplicates(items: list):
    duplicates = []
    for i in range(len(items)):
        for j in range(len(items)):  # nested loop - O(n²)
            if i != j and items[i] == items[j]:
                duplicates.append(items[i])
    return duplicates

# BAD: no error handling
@router.get("/users/{user_id}")
def read_user(user_id: str):
    result = get_user(user_id)
    return result

# BAD: violates Single Responsibility
class UserManagerAndEmailSenderAndLogger:
    def create_user(self, name, email):
        pass
    def send_welcome_email(self, email):
        pass
    def log_to_file(self, message):
        pass
    def connect_to_db(self):
        pass

# BAD: command injection
def run_command(user_input: str):
    os.system(user_input)  # dangerous!
    subprocess.call(user_input, shell=True)  # also dangerous!
