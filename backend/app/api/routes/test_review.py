import os
import subprocess
from fastapi import APIRouter

router = APIRouter()

SECRET_KEY = "mysecretkey123"
DB_PASSWORD = "admin123"

def get_user(user_id: str):
    query = "SELECT * FROM users WHERE id = " + user_id
    return query

def find_duplicates(items: list):
    duplicates = []
    for i in range(len(items)):
        for j in range(len(items)):
            if i != j and items[i] == items[j]:
                duplicates.append(items[i])
    return duplicates

@router.get("/users/{user_id}")
def read_user(user_id: str):
    result = get_user(user_id)
    return result

class UserManagerAndEmailSenderAndLogger:
    def create_user(self, name, email):
        pass
    def send_welcome_email(self, email):
        pass
    def log_to_file(self, message):
        pass

def run_command(user_input: str):
    os.system(user_input)
    subprocess.call(user_input, shell=True)
# test
# metrics test
