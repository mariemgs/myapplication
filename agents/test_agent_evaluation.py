"""
AI Code Review Agent - Evaluation Test Suite
50 known issues: Security(10) + SOLID(10) + Performance(10) + FastAPI(10) + Python(10)
Detection: Keyword matching only (reproducible, objective, explainable)
Measures: Detection Rate per category + Hallucination Rate
"""

import os
import json
import time
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage

llm = ChatGroq(
    model="llama-3.3-70b-versatile",
    temperature=0.1,
    api_key=os.environ.get("GROQ_API_KEY"),
)


def llm_invoke_with_retry(messages, max_retries=5):
    """LLM call with exponential backoff on rate limit errors."""
    for attempt in range(max_retries):
        try:
            return llm.invoke(messages).content
        except Exception as e:
            if "429" in str(e) or "rate limit" in str(e).lower():
                wait = 30 * (attempt + 1)
                print("    Rate limit - waiting {}s (retry {}/{})...".format(
                    wait, attempt + 1, max_retries))
                time.sleep(wait)
            else:
                return "Error: {}".format(e)
    return "Error: max retries exceeded"


# ── 50 Test Cases ─────────────────────────────────────────────────────────────

TEST_CASES = [

    # ════════════════════════════════════════════════════════════════
    # SECURITY (10) - Tested by Pass 1
    # ════════════════════════════════════════════════════════════════
    {
        "id": "SEC-01", "category": "Security",
        "known_issue": "SQL Injection via string concatenation",
        "keywords": ["sql injection", "injection", "concatenat", "string concat",
                     "parameteriz", "raw query", "user input", "unsanitized"],
        "code": '''
def get_user(user_id: str):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
'''
    },
    {
        "id": "SEC-02", "category": "Security",
        "known_issue": "Hardcoded credentials in source code",
        "keywords": ["hardcoded", "hard-coded", "secret", "password", "credential",
                     "environment variable", "plaintext", "sensitive", "source code"],
        "code": '''
DATABASE_PASSWORD = "admin123"
SECRET_KEY = "mysupersecretkey"
API_TOKEN = "ghp_abc123realtoken"
'''
    },
    {
        "id": "SEC-03", "category": "Security",
        "known_issue": "Command injection via os.system with user input",
        "keywords": ["command injection", "os.system", "shell=true", "shell=True",
                     "injection", "arbitrary command", "user-controlled", "sanitize"],
        "code": '''
def run_command(user_input: str):
    os.system(user_input)
    subprocess.call(user_input, shell=True)
'''
    },
    {
        "id": "SEC-04", "category": "Security",
        "known_issue": "Missing authentication on sensitive delete endpoint",
        "keywords": ["authentication", "authorization", "current_user", "permission",
                     "unauthenticated", "protected", "any user", "without auth", "auth"],
        "code": '''
@router.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    db.delete(user)
    db.commit()
    return {"message": "deleted"}
'''
    },
    {
        "id": "SEC-05", "category": "Security",
        "known_issue": "Insecure random number for security token",
        "keywords": ["random", "insecure", "secrets module", "cryptograph",
                     "predictable", "secure random", "os.urandom", "pseudo"],
        "code": '''
import random
def generate_reset_token():
    return str(random.randint(100000, 999999))
'''
    },
    {
        "id": "SEC-06", "category": "Security",
        "known_issue": "Path traversal vulnerability in file upload",
        "keywords": ["path traversal", "filename", "sanitiz", "../",
                     "directory traversal", "arbitrary file", "malicious", "secure_filename"],
        "code": '''
@router.post("/upload")
async def upload_file(file: UploadFile):
    file_path = f"uploads/{file.filename}"
    with open(file_path, "wb") as f:
        content = await file.read()
        f.write(content)
    return {"path": file_path}
'''
    },
    {
        "id": "SEC-07", "category": "Security",
        "known_issue": "Sensitive password exposed in logs",
        "keywords": ["log", "password", "sensitive", "expose", "leak",
                     "logging", "never log", "plain", "credentials in log"],
        "code": '''
def authenticate(username: str, password: str):
    logger.info(f"Login attempt: username={username}, password={password}")
    user = db.query(User).filter(User.username == username).first()
    return user
'''
    },
    {
        "id": "SEC-08", "category": "Security",
        "known_issue": "JWT token created without expiration",
        "keywords": ["expir", "exp", "jwt", "token", "lifetime",
                     "never expire", "no expiration", "expiration time"],
        "code": '''
def create_token(user_id: int):
    payload = {"sub": str(user_id)}
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token
'''
    },
    {
        "id": "SEC-09", "category": "Security",
        "known_issue": "Mass assignment vulnerability via setattr loop",
        "keywords": ["mass assignment", "whitelist", "setattr", "arbitrary field",
                     "all fields", "allowlist", "unexpected field", "any attribute"],
        "code": '''
@router.put("/users/{user_id}")
def update_user(user_id: int, user_data: dict, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    for key, value in user_data.items():
        setattr(user, key, value)
    db.commit()
    return user
'''
    },
    {
        "id": "SEC-10", "category": "Security",
        "known_issue": "Password stored as plain text without hashing",
        "keywords": ["hash", "bcrypt", "plain text", "plain-text", "hashed",
                     "encrypt", "passlib", "never store", "password hash"],
        "code": '''
@router.post("/users")
def create_user(username: str, password: str, db: Session = Depends(get_db)):
    user = User(username=username, password=password)
    db.add(user)
    db.commit()
    return {"id": user.id}
'''
    },

    # ════════════════════════════════════════════════════════════════
    # SOLID (10) - Tested by Pass 2
    # ════════════════════════════════════════════════════════════════
    {
        "id": "SOLID-01", "category": "SOLID",
        "known_issue": "SRP violation - God class with too many responsibilities",
        "keywords": ["single responsibility", "srp", "god class", "multiple responsibilities",
                     "too many concerns", "separate class", "violates", "one reason to change"],
        "code": '''
class UserManager:
    def create_user(self, name, email, password): pass
    def send_welcome_email(self, email): pass
    def generate_pdf_report(self, user_id): pass
    def connect_to_database(self): pass
    def log_to_file(self, message): pass
    def validate_credit_card(self, card_number): pass
    def send_sms(self, phone, message): pass
'''
    },
    {
        "id": "SOLID-02", "category": "SOLID",
        "known_issue": "OCP violation - if/elif chain requiring modification for new types",
        "keywords": ["open/closed", "ocp", "if-elif", "if/elif", "extension",
                     "polymorphism", "modification", "closed for modification", "new type"],
        "code": '''
class PaymentProcessor:
    def process(self, payment_type: str, amount: float):
        if payment_type == "credit_card":
            pass
        elif payment_type == "paypal":
            pass
        elif payment_type == "bitcoin":
            pass
'''
    },
    {
        "id": "SOLID-03", "category": "SOLID",
        "known_issue": "DIP violation - depending on concrete class directly",
        "keywords": ["dependency inversion", "dip", "concrete", "abstraction",
                     "interface", "inject", "tightly coupled", "direct instantiation"],
        "code": '''
class OrderService:
    def __init__(self):
        self.db = MySQLDatabase()
        self.emailer = GmailEmailer()
    def place_order(self, order):
        self.db.save(order)
        self.emailer.send_confirmation(order)
'''
    },
    {
        "id": "SOLID-04", "category": "SOLID",
        "known_issue": "DRY violation - duplicated validation logic",
        "keywords": ["dry", "duplicate", "repeated", "extract", "reuse",
                     "identical", "code duplication", "refactor", "same logic"],
        "code": '''
def validate_user_email(email: str):
    if not email or "@" not in email:
        raise ValueError("Invalid email")
    if len(email) > 255:
        raise ValueError("Email too long")
    return email.lower().strip()

def validate_admin_email(email: str):
    if not email or "@" not in email:
        raise ValueError("Invalid email")
    if len(email) > 255:
        raise ValueError("Email too long")
    return email.lower().strip()
'''
    },
    {
        "id": "SOLID-05", "category": "SOLID",
        "known_issue": "ISP violation - function with too many boolean flags",
        "keywords": ["boolean flag", "flag parameter", "too many parameter",
                     "separate method", "interface segregation", "responsibility", "split"],
        "code": '''
def process_user_data(user_id, update_profile=False,
                      send_email=False, generate_report=False,
                      delete_account=False, export_data=False):
    user = get_user(user_id)
    if update_profile: update_user_profile(user)
    if send_email: send_notification_email(user)
    if generate_report: create_user_report(user)
    if delete_account: delete_user_account(user)
    if export_data: export_user_data(user)
'''
    },
    {
        "id": "SOLID-06", "category": "SOLID",
        "known_issue": "LSP violation - subclass raises exception for parent method",
        "keywords": ["liskov", "lsp", "subclass", "inheritance", "substitut",
                     "cannot fly", "base class", "violates", "exception in subclass"],
        "code": '''
class Bird:
    def fly(self):
        return "flying"

class Penguin(Bird):
    def fly(self):
        raise Exception("Penguins cannot fly!")

def make_bird_fly(bird: Bird):
    return bird.fly()
'''
    },
    {
        "id": "SOLID-07", "category": "SOLID",
        "known_issue": "KISS violation - over-engineered solution for simple addition",
        "keywords": ["kiss", "over-engineer", "overcomplicated", "unnecessary",
                     "simpler", "complex", "needlessly", "simple addition"],
        "code": '''
class NumberAdderFactoryBuilderStrategy:
    def __init__(self):
        self.strategy = None
    def set_strategy(self, strategy):
        self.strategy = strategy
        return self
    def build(self):
        return self
    def execute(self, a, b):
        return a + b
'''
    },
    {
        "id": "SOLID-08", "category": "SOLID",
        "known_issue": "Tight coupling to concrete library implementation",
        "keywords": ["coupling", "tightly coupled", "hard dependency", "abstraction",
                     "difficult to test", "swap", "depend on concrete", "direct import"],
        "code": '''
class ReportGenerator:
    def generate(self, data):
        import pandas as pd
        df = pd.DataFrame(data)
        df.to_csv("report.csv")
        df.to_excel("report.xlsx")
        return df.to_html()
'''
    },
    {
        "id": "SOLID-09", "category": "SOLID",
        "known_issue": "Long method doing too many responsibilities",
        "keywords": ["long method", "too many", "extract", "responsibility",
                     "decompose", "multiple steps", "separate function", "does too much"],
        "code": '''
def process_order(order_id: int):
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order: raise ValueError("Order not found")
    subtotal = sum(item.price * item.qty for item in order.items)
    tax = subtotal * 0.19
    discount = subtotal * 0.1 if subtotal > 100 else 0
    total = subtotal + tax - discount
    charge_result = payment_gateway.charge(order.user.card, total)
    if not charge_result.success: raise ValueError("Payment failed")
    order.status = "paid"
    order.total = total
    db.commit()
    send_email(order.user.email, "Order confirmed", total)
    send_sms(order.user.phone, f"Order {order_id} paid")
    logger.info(f"Order {order_id} processed: {total}")
'''
    },
    {
        "id": "SOLID-10", "category": "SOLID",
        "known_issue": "Magic numbers without named constants",
        "keywords": ["magic number", "magic value", "named constant", "0.85", "0.70",
                     "hardcoded value", "meaningful name", "constant", "named"],
        "code": '''
def calculate_discount(price: float, user_type: str) -> float:
    if user_type == "premium":
        return price * 0.85
    elif user_type == "vip":
        return price * 0.70
    elif price > 500:
        return price * 0.95
    return price
'''
    },

    # ════════════════════════════════════════════════════════════════
    # PERFORMANCE (10) - Tested by Pass 3
    # ════════════════════════════════════════════════════════════════
    {
        "id": "PERF-01", "category": "Performance",
        "known_issue": "O(n²) nested loop for finding duplicates",
        "keywords": ["o(n", "quadratic", "nested loop", "n^2", "n squared",
                     "inefficient", "inner loop", "set(", "complexity"],
        "code": '''
def find_duplicates(items: list):
    duplicates = []
    for i in range(len(items)):
        for j in range(len(items)):
            if i != j and items[i] == items[j]:
                duplicates.append(items[i])
    return duplicates
'''
    },
    {
        "id": "PERF-02", "category": "Performance",
        "known_issue": "N+1 database query problem in loop",
        "keywords": ["n+1", "multiple queries", "loop query", "joinedload",
                     "selectinload", "eager loading", "join", "batch", "single query"],
        "code": '''
def get_all_user_orders():
    users = db.query(User).all()
    result = []
    for user in users:
        orders = db.query(Order).filter(Order.user_id == user.id).all()
        result.append({"user": user, "orders": orders})
    return result
'''
    },
    {
        "id": "PERF-03", "category": "Performance",
        "known_issue": "Blocking synchronous I/O in async FastAPI endpoint",
        "keywords": ["async", "await", "blocking", "asyncio", "httpx",
                     "synchronous", "sync", "non-blocking", "event loop"],
        "code": '''
@router.get("/data")
def fetch_external_data():
    import requests
    response = requests.get("https://api.external.com/data")
    time.sleep(2)
    return response.json()
'''
    },
    {
        "id": "PERF-04", "category": "Performance",
        "known_issue": "Missing memoization on recursive fibonacci",
        "keywords": ["cache", "lru_cache", "memoiz", "recursive", "exponential",
                     "redundant", "recomput", "functools", "2^n"],
        "code": '''
def get_fibonacci(n: int) -> int:
    if n <= 1:
        return n
    return get_fibonacci(n - 1) + get_fibonacci(n - 2)
'''
    },
    {
        "id": "PERF-05", "category": "Performance",
        "known_issue": "Inefficient string concatenation with + in loop",
        "keywords": ["concatenat", "join", "list comprehension", "inefficient",
                     "string builder", "quadratic", "+=", "append", "str.join"],
        "code": '''
def build_report(items):
    report = ""
    for item in items:
        report = report + str(item) + ", "
    return report
'''
    },
    {
        "id": "PERF-06", "category": "Performance",
        "known_issue": "Loading all database records without pagination",
        "keywords": ["pagination", "limit", "offset", "all()", "memory",
                     "large dataset", "skip", "page", "performance"],
        "code": '''
@router.get("/users")
def get_all_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return users
'''
    },
    {
        "id": "PERF-07", "category": "Performance",
        "known_issue": "Using list instead of set for O(n) membership test",
        "keywords": ["set", "o(1)", "list lookup", "o(n)", "constant time",
                     "hash", "membership test", "convert to set", "lookup"],
        "code": '''
BLOCKED_IPS = ["192.168.1.1", "10.0.0.1", "172.16.0.1",
               "192.168.1.2", "10.0.0.2"]

def is_blocked(ip: str) -> bool:
    return ip in BLOCKED_IPS
'''
    },
    {
        "id": "PERF-08", "category": "Performance",
        "known_issue": "Unnecessary intermediate list in sum/len operations",
        "keywords": ["generator", "intermediate list", "memory", "generator expression",
                     "unnecessary list", "sum(x", "len(x", "list comprehension"],
        "code": '''
def get_adult_count(users: list) -> int:
    adults = [u for u in users if u.age >= 18]
    return len(adults)

def get_total_price(items: list) -> float:
    prices = [item.price for item in items]
    return sum(prices)
'''
    },
    {
        "id": "PERF-09", "category": "Performance",
        "known_issue": "Repeated dictionary lookup instead of defaultdict",
        "keywords": ["defaultdict", "counter", "collections", "dict.get",
                     "setdefault", "Counter", "efficient", "get("],
        "code": '''
def count_words(text: str) -> dict:
    counts = {}
    for word in text.split():
        if word in counts:
            counts[word] = counts[word] + 1
        else:
            counts[word] = 1
    return counts
'''
    },
    {
        "id": "PERF-10", "category": "Performance",
        "known_issue": "Missing database index on frequently queried column",
        "keywords": ["index", "Index(", "database index", "query performance",
                     "__table_args__", "indexed", "add index", "slow query"],
        "code": '''
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True)
    username = Column(String)
    created_at = Column(DateTime)

def find_by_username(username: str):
    return db.query(User).filter(User.username == username).first()
'''
    },

    # ════════════════════════════════════════════════════════════════
    # FASTAPI (10) - Pass 1 catches these (security + quality)
    # ════════════════════════════════════════════════════════════════
    {
        "id": "FASTAPI-01", "category": "FastAPI",
        "known_issue": "Missing response_model exposing internal fields",
        "keywords": ["response_model", "schema", "expose", "sensitive field",
                     "pydantic", "internal", "return type", "model"],
        "code": '''
@router.get("/users/{user_id}")
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    return user
'''
    },
    {
        "id": "FASTAPI-02", "category": "FastAPI",
        "known_issue": "Missing HTTP 201 status code on create endpoint",
        "keywords": ["status_code", "201", "HTTP status", "created",
                     "status code", "response status", "post endpoint"],
        "code": '''
@router.post("/users")
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = User(**user.dict())
    db.add(db_user)
    db.commit()
    return db_user
'''
    },
    {
        "id": "FASTAPI-03", "category": "FastAPI",
        "known_issue": "No HTTPException when item not found returns None",
        "keywords": ["404", "HTTPException", "not found", "none check",
                     "if not", "raise", "missing item", "null"],
        "code": '''
@router.get("/items/{item_id}")
def get_item(item_id: int, db: Session = Depends(get_db)):
    item = db.query(Item).filter(Item.id == item_id).first()
    return item
'''
    },
    {
        "id": "FASTAPI-04", "category": "FastAPI",
        "known_issue": "Missing Pydantic model for request body validation",
        "keywords": ["pydantic", "validation", "schema", "BaseModel",
                     "request body", "type safety", "model", "validator"],
        "code": '''
@router.post("/register")
def register(username: str, email: str, age: int, db: Session = Depends(get_db)):
    user = User(username=username, email=email, age=age)
    db.add(user)
    db.commit()
    return user
'''
    },
    {
        "id": "FASTAPI-05", "category": "FastAPI",
        "known_issue": "Raw psycopg2 connection without SQLAlchemy session",
        "keywords": ["connection pool", "SQLAlchemy", "session", "Depends",
                     "raw connection", "psycopg2", "direct connection", "manage"],
        "code": '''
@router.get("/report")
def generate_report():
    conn = psycopg2.connect("postgresql://localhost/mydb")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders")
    results = cursor.fetchall()
    conn.close()
    return results
'''
    },
    {
        "id": "FASTAPI-06", "category": "FastAPI",
        "known_issue": "No rate limiting on login endpoint",
        "keywords": ["rate limit", "brute force", "slowapi", "throttl",
                     "attempt", "lockout", "too many requests", "limit"],
        "code": '''
@router.post("/login")
def login(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if user and verify_password(password, user.hashed_password):
        return create_access_token(user.id)
    raise HTTPException(status_code=401, detail="Invalid credentials")
'''
    },
    {
        "id": "FASTAPI-07", "category": "FastAPI",
        "known_issue": "No background task for long-running email operation",
        "keywords": ["background", "BackgroundTasks", "long-running", "task",
                     "worker", "blocking", "queue", "celery", "async"],
        "code": '''
@router.post("/send-newsletter")
def send_newsletter(db: Session = Depends(get_db)):
    users = db.query(User).all()
    for user in users:
        send_email(user.email, "Newsletter", get_newsletter_content())
    return {"message": "sent"}
'''
    },
    {
        "id": "FASTAPI-08", "category": "FastAPI",
        "known_issue": "Using os.getenv instead of Pydantic BaseSettings",
        "keywords": ["BaseSettings", "pydantic settings", "dependency injection",
                     "configuration", "settings class", "os.getenv", "env"],
        "code": '''
@router.get("/config")
def get_config():
    import os
    return {
        "debug": os.getenv("DEBUG", "false"),
        "db_host": os.getenv("DB_HOST", "localhost"),
    }
'''
    },
    {
        "id": "FASTAPI-09", "category": "FastAPI",
        "known_issue": "CORS configured to allow all origins with credentials",
        "keywords": ["cors", "allow_origins", "wildcard", "allow_credentials",
                     "misconfigur", "restrict", "all origins", "insecure cors"],
        "code": '''
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
'''
    },
    {
        "id": "FASTAPI-10", "category": "FastAPI",
        "known_issue": "No None check before db.delete causing potential crash",
        "keywords": ["404", "HTTPException", "none", "not found", "if not",
                     "raise", "null check", "missing", "attribute error"],
        "code": '''
@router.delete("/posts/{post_id}")
def delete_post(post_id: int, db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id).first()
    db.delete(post)
    db.commit()
    return {"deleted": post_id}
'''
    },

    # ════════════════════════════════════════════════════════════════
    # PYTHON BEST PRACTICES (10) - Pass 2 + 3 catch these
    # ════════════════════════════════════════════════════════════════
    {
        "id": "PY-01", "category": "Python",
        "known_issue": "Mutable default argument - list shared across calls",
        "keywords": ["mutable default", "mutable default argument", "default argument",
                     "items = none", "evaluated once", "shared state", "items=[]"],
        "code": '''
def add_item(item: str, items: list = []):
    items.append(item)
    return items
'''
    },
    {
        "id": "PY-02", "category": "Python",
        "known_issue": "Bare except clause catching all exceptions",
        "keywords": ["bare except", "except:", "specific exception", "too broad",
                     "general exception", "catch all", "silent", "swallow"],
        "code": '''
def read_config(filepath: str):
    try:
        with open(filepath) as f:
            return json.load(f)
    except:
        return {}
'''
    },
    {
        "id": "PY-03", "category": "Python",
        "known_issue": "File opened without context manager - resource leak",
        "keywords": ["context manager", "with statement", "with open",
                     "resource leak", "file handle", "properly close", "f.close"],
        "code": '''
def read_file(path: str) -> str:
    f = open(path, "r")
    content = f.read()
    f.close()
    return content
'''
    },
    {
        "id": "PY-04", "category": "Python",
        "known_issue": "Using type() instead of isinstance() for type checking",
        "keywords": ["isinstance", "type()", "preferred", "type check",
                     "subclass", "polymorphism", "isinstance()"],
        "code": '''
def process_value(value):
    if type(value) == int:
        return value * 2
    elif type(value) == str:
        return value.upper()
    elif type(value) == list:
        return len(value)
'''
    },
    {
        "id": "PY-05", "category": "Python",
        "known_issue": "Using range(len()) instead of enumerate()",
        "keywords": ["enumerate", "range(len", "pythonic", "idiomatic",
                     "unpythonic", "enumerate(", "index"],
        "code": '''
def print_items(items: list):
    for i in range(len(items)):
        print(f"{i}: {items[i]}")
'''
    },
    {
        "id": "PY-06", "category": "Python",
        "known_issue": "Using old % string formatting instead of f-strings",
        "keywords": ["f-string", "format(", "% operator", "old style",
                     "preferred", ".format", "modern", "fstring", "f-strings"],
        "code": '''
def greet_user(name: str, age: int) -> str:
    return "Hello %s, you are %d years old" % (name, age)

def log_error(error: str, code: int) -> str:
    return "Error %d: %s" % (code, error)
'''
    },
    {
        "id": "PY-07", "category": "Python",
        "known_issue": "Missing type hints on function parameters",
        "keywords": ["type hint", "annotation", "typing", "return type",
                     "missing type", "type annotation", "->", ": int", ": str"],
        "code": '''
def calculate_total(items, tax_rate, discount):
    subtotal = sum(item["price"] * item["qty"] for item in items)
    tax = subtotal * tax_rate
    return subtotal + tax - discount
'''
    },
    {
        "id": "PY-08", "category": "Python",
        "known_issue": "Global variable mutation - not thread safe",
        "keywords": ["global", "global variable", "mutation", "thread safe",
                     "side effect", "avoid global", "encapsulat"],
        "code": '''
request_count = 0
error_count = 0

def handle_request(request):
    global request_count
    request_count += 1
    try:
        return process(request)
    except Exception:
        global error_count
        error_count += 1
'''
    },
    {
        "id": "PY-09", "category": "Python",
        "known_issue": "Comparing to None with == instead of is",
        "keywords": ["is none", "is not none", "== none", "pep 8",
                     "identity", "singleton", "is operator", "comparison"],
        "code": '''
def get_user_name(user):
    if user == None:
        return "Anonymous"
    if user.name == None:
        return "No name"
    return user.name
'''
    },
    {
        "id": "PY-10", "category": "Python",
        "known_issue": "Using plain dict instead of dataclass or Pydantic model",
        "keywords": ["dataclass", "pydantic", "BaseModel", "TypedDict",
                     "named tuple", "NamedTuple", "data class", "structured"],
        "code": '''
def create_user_dict(name, email, age, role, is_active):
    return {
        "name": name,
        "email": email,
        "age": age,
        "role": role,
        "is_active": is_active,
    }
'''
    },
]


# ── Review passes ─────────────────────────────────────────────────────────────

def run_pass1_security(code):
    """Pass 1: Security and code quality."""
    system = (
        "You are a security and code quality expert.\n"
        "Find ALL issues in this code:\n"
        "- Security vulnerabilities (injection, secrets, auth, OWASP Top 10)\n"
        "- Missing error handling\n"
        "- Missing input validation\n"
        "- Bad practices and anti-patterns\n"
        "Be thorough. List every issue you find with the line number."
    )
    return llm_invoke_with_retry([
        SystemMessage(content=system),
        HumanMessage(content="Review this code:\n```python\n{}\n```".format(code))
    ])


def run_pass2_solid(code):
    """Pass 2: SOLID principles and architecture."""
    system = (
        "You are a software architecture expert.\n"
        "Find ALL issues in this code:\n"
        "- SOLID violations (SRP, OCP, LSP, ISP, DIP)\n"
        "- DRY violations (duplicated code)\n"
        "- KISS violations (over-engineering)\n"
        "- Magic numbers without named constants\n"
        "- Long methods doing too much\n"
        "- Tight coupling\n"
        "Be thorough. List every issue you find with the line number."
    )
    return llm_invoke_with_retry([
        SystemMessage(content=system),
        HumanMessage(content="Review this code:\n```python\n{}\n```".format(code))
    ])


def run_pass3_optimization(code):
    """Pass 3: Performance and Python best practices."""
    system = (
        "You are a Python performance and best practices expert.\n"
        "Find ALL issues in this code:\n"
        "- Time complexity issues (O(n^2), N+1 queries)\n"
        "- Blocking I/O that should be async\n"
        "- Missing caching/memoization\n"
        "- Inefficient data structures\n"
        "- Python anti-patterns (mutable defaults, bare except, range(len))\n"
        "- Missing type hints\n"
        "- Old-style formatting instead of f-strings\n"
        "Be thorough. List every issue with the line number."
    )
    return llm_invoke_with_retry([
        SystemMessage(content=system),
        HumanMessage(content="Review this code:\n```python\n{}\n```".format(code))
    ])


def run_pass4_validation(code, p1, p2, p3):
    """Pass 4: Anti-hallucination validation."""
    system = (
        "You are a strict fact-checker for code reviews.\n"
        "Validate that every issue mentioned actually exists in the code.\n\n"
        "For each issue:\n"
        "- If the issue EXISTS in the code: keep it as VALID\n"
        "- If the issue does NOT exist in the code: mark as HALLUCINATED\n\n"
        "Format your response EXACTLY as:\n"
        "## Validated Issues\n"
        "- [VALID] description\n\n"
        "## Removed (Hallucinated) Issues\n"
        "- [HALLUCINATED] description"
    )
    content = (
        "CODE:\n```python\n{}\n```\n\n"
        "PASS 1 (Security):\n{}\n\n"
        "PASS 2 (SOLID):\n{}\n\n"
        "PASS 3 (Performance):\n{}\n\n"
        "Validate every finding against the actual code."
    ).format(code, p1[:1000], p2[:1000], p3[:1000])
    return llm_invoke_with_retry([
        SystemMessage(content=system),
        HumanMessage(content=content)
    ])


# ── Detection and counting ────────────────────────────────────────────────────

def keyword_detect(review_text, keywords):
    """Check if any keyword appears in the review."""
    text_lower = review_text.lower()
    for kw in keywords:
        if kw.lower() in text_lower:
            return True
    return False


def count_section(text, marker):
    """Count bullet points in a named section."""
    count = 0
    in_section = False
    for line in text.split("\n"):
        if marker.lower() in line.lower() and line.strip().startswith("#"):
            in_section = True
        elif line.strip().startswith("##") and marker.lower() not in line.lower():
            in_section = False
        elif in_section and line.strip().startswith("-") and len(line.strip()) > 3:
            count += 1
    return count


# ── Main evaluation ───────────────────────────────────────────────────────────

def run_evaluation():
    print("=" * 65)
    print("AI CODE REVIEW AGENT - EVALUATION SUITE")
    print("Method  : Keyword-based detection (objective & reproducible)")
    print("Passes  : Security | SOLID | Performance | Anti-hallucination")
    print("Cases   : {}".format(len(TEST_CASES)))
    print("=" * 65)
    print()

    results = []
    total_detected    = 0
    total_hallucinated = 0
    total_validated   = 0

    for i, test in enumerate(TEST_CASES):
        print("[{:02d}/{}] {} — {}".format(
            i + 1, len(TEST_CASES), test["id"], test["known_issue"]))

        start = time.time()

        # Run 4 passes
        p1 = run_pass1_security(test["code"])
        p2 = run_pass2_solid(test["code"])
        p3 = run_pass3_optimization(test["code"])
        p4 = run_pass4_validation(test["code"], p1, p2, p3)

        combined = p1 + "\n" + p2 + "\n" + p3

        # Detection via keywords
        detected = keyword_detect(combined, test["keywords"])

        # Count Pass 4 findings
        hall  = count_section(p4, "Hallucinated")
        valid = count_section(p4, "Validated Issues")

        duration = time.time() - start

        total_detected    += 1 if detected else 0
        total_hallucinated += hall
        total_validated   += valid

        status = "DETECTED ✓" if detected else "MISSED   ✗"
        print("  {} | Valid: {:2d} | Halluc: {:2d} | {:.1f}s".format(
            status, valid, hall, duration))

        results.append({
            "id"                  : test["id"],
            "category"            : test["category"],
            "known_issue"         : test["known_issue"],
            "detected"            : detected,
            "validated_findings"  : valid,
            "hallucinated_findings": hall,
            "duration_seconds"    : round(duration, 1),
        })

        time.sleep(2)  # avoid rate limit between tests

    # ── Final report ─────────────────────────────────────────────────────────
    total      = len(TEST_CASES)
    det_rate   = total_detected / total * 100
    total_raw  = total_validated + total_hallucinated
    hall_rate  = (total_hallucinated / total_raw * 100) if total_raw > 0 else 0

    print()
    print("=" * 65)
    print("FINAL EVALUATION RESULTS")
    print("=" * 65)
    print()

    categories = ["Security", "SOLID", "Performance", "FastAPI", "Python"]
    print("DETECTION BY CATEGORY:")
    print()
    for cat in categories:
        cat_res = [r for r in results if r["category"] == cat]
        det = sum(1 for r in cat_res if r["detected"])
        n   = len(cat_res)
        bar = "#" * det + "-" * (n - det)
        pct = det / n * 100 if n > 0 else 0
        print("  {:<13} [{:<10}] {:>2}/{:>2}  ({:.0f}%)".format(
            cat, bar, det, n, pct))

    print()
    print("OVERALL DETECTION METRICS:")
    print("  Total test cases         : {:>3}".format(total))
    print("  Correctly detected       : {:>3}".format(total_detected))
    print("  Missed                   : {:>3}".format(total - total_detected))
    print("  Detection Rate           : {:.1f}%".format(det_rate))
    print()
    print("ANTI-HALLUCINATION METRICS (Pass 4):")
    print("  Total raw findings       : {:>3}".format(total_raw))
    print("  Validated (kept)         : {:>3}".format(total_validated))
    print("  Hallucinated (removed)   : {:>3}".format(total_hallucinated))
    print("  Hallucination Rate       : {:.1f}%".format(hall_rate))
    print("  Filter Accuracy          : {:.1f}%".format(100 - hall_rate))
    print()

    print("DETAILED RESULTS:")
    print("-" * 75)
    print("{:<12} {:<13} {:<32} {:<10} {:>6}".format(
        "ID", "Category", "Known Issue", "Detected", "Halluc"))
    print("-" * 75)
    for r in results:
        print("{:<12} {:<13} {:<32} {:<10} {:>6}".format(
            r["id"], r["category"], r["known_issue"][:30],
            "YES" if r["detected"] else "NO",
            r["hallucinated_findings"]
        ))
    print("-" * 75)

    # Save JSON
    output = {
        "evaluation_method": "Keyword-based detection (objective, reproducible)",
        "summary": {
            "total_tests"         : total,
            "detected"            : total_detected,
            "missed"              : total - total_detected,
            "detection_rate"      : round(det_rate, 1),
            "total_raw_findings"  : total_raw,
            "total_validated"     : total_validated,
            "total_hallucinated"  : total_hallucinated,
            "hallucination_rate"  : round(hall_rate, 1),
            "filter_accuracy"     : round(100 - hall_rate, 1),
        },
        "by_category": {
            cat: {
                "detected"      : sum(1 for r in results if r["category"] == cat and r["detected"]),
                "total"         : len([r for r in results if r["category"] == cat]),
                "detection_rate": round(
                    sum(1 for r in results if r["category"] == cat and r["detected"]) /
                    max(len([r for r in results if r["category"] == cat]), 1) * 100, 1)
            }
            for cat in categories
        },
        "detailed_results": results
    }

    with open("evaluation_results.json", "w") as f:
        json.dump(output, f, indent=2)

    print()
    print("Results saved to evaluation_results.json")
    print("=" * 65)
    return output


if __name__ == "__main__":
    run_evaluation()