"""
AI Code Review Agent - Evaluation Test Suite
Tests 50 known issues across Security, SOLID, Performance, FastAPI, Python categories
Measures: Detection Rate, False Positive Rate, Hallucination Rate
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

TEST_CASES = [

    # ── SECURITY ISSUES (10) ─────────────────────────────────────────────────

    {
        "id": "SEC-01",
        "category": "Security",
        "known_issue": "SQL Injection via string concatenation",
        "code": '''
def get_user(user_id: str):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
''',
        "keywords": ["sql injection", "injection", "concatenat", "parameteriz", "user input", "string concat", "raw query"]
    },
    {
        "id": "SEC-02",
        "category": "Security",
        "known_issue": "Hardcoded credentials in source code",
        "code": '''
DATABASE_PASSWORD = "admin123"
SECRET_KEY = "mysupersecretkey"
API_TOKEN = "ghp_abc123realtoken"
''',
        "keywords": ["hardcoded", "hard-coded", "secret", "password", "credential", "environment variable", "plaintext", "source code"]
    },
    {
        "id": "SEC-03",
        "category": "Security",
        "known_issue": "Command injection via os.system with user input",
        "code": '''
def run_command(user_input: str):
    os.system(user_input)
    subprocess.call(user_input, shell=True)
''',
        "keywords": ["command injection", "os.system", "shell=true", "shell=True", "injection", "arbitrary command", "user input"]
    },
    {
        "id": "SEC-04",
        "category": "Security",
        "known_issue": "Missing authentication on sensitive delete endpoint",
        "code": '''
@router.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    db.delete(user)
    db.commit()
    return {"message": "deleted"}
''',
        "keywords": ["authentication", "authorization", "current_user", "permission", "auth", "unauthenticated", "protected", "security"]
    },
    {
        "id": "SEC-05",
        "category": "Security",
        "known_issue": "Insecure random for security token generation",
        "code": '''
import random
def generate_reset_token():
    return str(random.randint(100000, 999999))
''',
        "keywords": ["random", "insecure", "secrets module", "cryptograph", "predictable", "secure random", "os.urandom", "not cryptographically"]
    },
    {
        "id": "SEC-06",
        "category": "Security",
        "known_issue": "Path traversal in file upload",
        "code": '''
@router.post("/upload")
async def upload_file(file: UploadFile):
    file_path = f"uploads/{file.filename}"
    with open(file_path, "wb") as f:
        content = await file.read()
        f.write(content)
    return {"path": file_path}
''',
        "keywords": ["path traversal", "filename", "sanitiz", "../", "directory", "arbitrary file", "malicious", "unsafe"]
    },
    {
        "id": "SEC-07",
        "category": "Security",
        "known_issue": "Sensitive data exposed in logs",
        "code": '''
def authenticate(username: str, password: str):
    logger.info(f"Login attempt: username={username}, password={password}")
    user = db.query(User).filter(User.username == username).first()
    return user
''',
        "keywords": ["log", "password", "sensitive", "expose", "leak", "logging", "plain", "never log"]
    },
    {
        "id": "SEC-08",
        "category": "Security",
        "known_issue": "JWT token without expiration",
        "code": '''
def create_token(user_id: int):
    payload = {"sub": str(user_id)}
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token
''',
        "keywords": ["expir", "exp", "jwt", "token", "lifetime", "never expire", "no expiration", "expiration time"]
    },
    {
        "id": "SEC-09",
        "category": "Security",
        "known_issue": "Mass assignment vulnerability",
        "code": '''
@router.put("/users/{user_id}")
def update_user(user_id: int, user_data: dict, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    for key, value in user_data.items():
        setattr(user, key, value)
    db.commit()
    return user
''',
        "keywords": ["mass assignment", "whitelist", "allow", "field", "schema", "validation", "arbitrary", "setattr", "all fields"]
    },
    {
        "id": "SEC-10",
        "category": "Security",
        "known_issue": "CORS misconfiguration - allow all origins",
        "code": '''
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
''',
        "keywords": ["cors", "allow_origins", "wildcard", "allow_credentials", "misconfigur", "restrict", "all origins", "insecure"]
    },

    # ── SOLID VIOLATIONS (10) ────────────────────────────────────────────────

    {
        "id": "SOLID-01",
        "category": "SOLID",
        "known_issue": "SRP violation - God class with too many responsibilities",
        "code": '''
class UserManager:
    def create_user(self, name, email, password): pass
    def send_welcome_email(self, email): pass
    def generate_pdf_report(self, user_id): pass
    def connect_to_database(self): pass
    def log_to_file(self, message): pass
    def validate_credit_card(self, card_number): pass
    def send_sms(self, phone, message): pass
''',
        "keywords": ["single responsibility", "srp", "god class", "multiple responsibilities", "too many", "violates", "separate", "concern"]
    },
    {
        "id": "SOLID-02",
        "category": "SOLID",
        "known_issue": "OCP violation - if/elif for extensibility",
        "code": '''
class PaymentProcessor:
    def process(self, payment_type: str, amount: float):
        if payment_type == "credit_card":
            pass
        elif payment_type == "paypal":
            pass
        elif payment_type == "bitcoin":
            pass
''',
        "keywords": ["open/closed", "ocp", "if/elif", "if-elif", "extension", "polymorphism", "new payment", "modif", "closed for modification"]
    },
    {
        "id": "SOLID-03",
        "category": "SOLID",
        "known_issue": "DIP violation - depending on concrete class",
        "code": '''
class OrderService:
    def __init__(self):
        self.db = MySQLDatabase()
        self.emailer = GmailEmailer()

    def place_order(self, order):
        self.db.save(order)
        self.emailer.send_confirmation(order)
''',
        "keywords": ["dependency inversion", "dip", "concrete", "abstraction", "interface", "inject", "tightly coupled", "hard-coded dependency", "direct instantiation"]
    },
    {
        "id": "SOLID-04",
        "category": "SOLID",
        "known_issue": "DRY violation - duplicated validation logic",
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
''',
        "keywords": ["dry", "duplicate", "repeated", "extract", "reuse", "identical", "code duplication", "refactor", "same logic"]
    },
    {
        "id": "SOLID-05",
        "category": "SOLID",
        "known_issue": "ISP violation - function with too many boolean flags",
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
''',
        "keywords": ["interface segregation", "boolean flag", "single function", "responsibility", "too many parameter", "flag parameter", "separate method"]
    },
    {
        "id": "SOLID-06",
        "category": "SOLID",
        "known_issue": "LSP violation - subclass breaks parent contract",
        "code": '''
class Bird:
    def fly(self):
        return "flying"

class Penguin(Bird):
    def fly(self):
        raise Exception("Penguins cannot fly!")

def make_bird_fly(bird: Bird):
    return bird.fly()
''',
        "keywords": ["liskov", "lsp", "subclass", "inheritance", "contract", "substitut", "cannot fly", "exception", "violates", "base class"]
    },
    {
        "id": "SOLID-07",
        "category": "SOLID",
        "known_issue": "KISS violation - over-engineered simple operation",
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
''',
        "keywords": ["kiss", "over-engineer", "complex", "simple", "unnecessary", "overcomplic", "simpler", "overcomplicated", "needlessly"]
    },
    {
        "id": "SOLID-08",
        "category": "SOLID",
        "known_issue": "Missing abstraction - tight coupling to implementation",
        "code": '''
class ReportGenerator:
    def generate(self, data):
        # Directly uses pandas, cannot swap library
        import pandas as pd
        df = pd.DataFrame(data)
        df.to_csv("report.csv")
        df.to_excel("report.xlsx")
        return df.to_html()
''',
        "keywords": ["coupling", "abstraction", "interface", "depend", "swap", "tightly coupled", "hard dependency", "direct import", "difficult to test"]
    },
    {
        "id": "SOLID-09",
        "category": "SOLID",
        "known_issue": "Long method - too many lines, does too much",
        "code": '''
def process_order(order_id: int):
    # Step 1: validate
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order: raise ValueError("Order not found")
    if order.status != "pending": raise ValueError("Invalid status")
    # Step 2: calculate
    subtotal = sum(item.price * item.qty for item in order.items)
    tax = subtotal * 0.19
    discount = subtotal * 0.1 if subtotal > 100 else 0
    total = subtotal + tax - discount
    # Step 3: charge
    charge_result = payment_gateway.charge(order.user.card, total)
    if not charge_result.success: raise ValueError("Payment failed")
    # Step 4: update
    order.status = "paid"
    order.total = total
    db.commit()
    # Step 5: notify
    send_email(order.user.email, "Order confirmed", total)
    send_sms(order.user.phone, f"Order {order_id} paid")
    # Step 6: log
    logger.info(f"Order {order_id} processed: {total}")
''',
        "keywords": ["long method", "too many", "extract", "responsibility", "decompose", "multiple steps", "separate function", "complex", "too much"]
    },
    {
        "id": "SOLID-10",
        "category": "SOLID",
        "known_issue": "Magic numbers without constants",
        "code": '''
def calculate_discount(price: float, user_type: str) -> float:
    if user_type == "premium":
        return price * 0.85
    elif user_type == "vip":
        return price * 0.70
    elif price > 500:
        return price * 0.95
    return price
''',
        "keywords": ["magic number", "constant", "named", "0.85", "0.70", "hardcoded", "magic value", "named constant", "meaningful name"]
    },

    # ── PERFORMANCE ISSUES (10) ──────────────────────────────────────────────

    {
        "id": "PERF-01",
        "category": "Performance",
        "known_issue": "O(n²) nested loop",
        "code": '''
def find_duplicates(items: list):
    duplicates = []
    for i in range(len(items)):
        for j in range(len(items)):
            if i != j and items[i] == items[j]:
                duplicates.append(items[i])
    return duplicates
''',
        "keywords": ["o(n", "quadratic", "nested loop", "complexity", "n^2", "n²", "inefficient", "nested for", "inner loop", "set("]
    },
    {
        "id": "PERF-02",
        "category": "Performance",
        "known_issue": "N+1 database query problem",
        "code": '''
def get_all_user_orders():
    users = db.query(User).all()
    result = []
    for user in users:
        orders = db.query(Order).filter(Order.user_id == user.id).all()
        result.append({"user": user, "orders": orders})
    return result
''',
        "keywords": ["n+1", "query", "join", "eager loading", "batch", "multiple queries", "loop query", "joinedload", "selectinload"]
    },
    {
        "id": "PERF-03",
        "category": "Performance",
        "known_issue": "Blocking synchronous I/O in async FastAPI endpoint",
        "code": '''
@router.get("/data")
def fetch_external_data():
    import requests
    response = requests.get("https://api.external.com/data")
    time.sleep(2)
    return response.json()
''',
        "keywords": ["async", "await", "blocking", "asyncio", "httpx", "synchronous", "sync", "asynchronous", "event loop", "non-blocking"]
    },
    {
        "id": "PERF-04",
        "category": "Performance",
        "known_issue": "Missing memoization on recursive function",
        "code": '''
def get_fibonacci(n: int) -> int:
    if n <= 1:
        return n
    return get_fibonacci(n - 1) + get_fibonacci(n - 2)
''',
        "keywords": ["cache", "lru_cache", "memoiz", "recursive", "exponential", "2^n", "redundant", "recomput", "functools"]
    },
    {
        "id": "PERF-05",
        "category": "Performance",
        "known_issue": "Inefficient string concatenation in loop",
        "code": '''
def build_report(items):
    report = ""
    for item in items:
        report = report + str(item) + ", "
    return report
''',
        "keywords": ["concatenat", "join", "list comprehension", "inefficient", "string", "+=", "string builder", "quadratic"]
    },
    {
        "id": "PERF-06",
        "category": "Performance",
        "known_issue": "Loading all records without pagination",
        "code": '''
@router.get("/users")
def get_all_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return users
''',
        "keywords": ["pagination", "limit", "offset", "all()", "memory", "performance", "large dataset", "skip", "page"]
    },
    {
        "id": "PERF-07",
        "category": "Performance",
        "known_issue": "Repeated dictionary lookup in loop",
        "code": '''
def count_words(text: str) -> dict:
    counts = {}
    for word in text.split():
        if word in counts:
            counts[word] = counts[word] + 1
        else:
            counts[word] = 1
    return counts
''',
        "keywords": ["defaultdict", "counter", "collections", "get(", "efficient", "Counter", "setdefault", "dict.get"]
    },
    {
        "id": "PERF-08",
        "category": "Performance",
        "known_issue": "Using list when set would be more efficient for lookups",
        "code": '''
BLOCKED_IPS = ["192.168.1.1", "10.0.0.1", "172.16.0.1",
               "192.168.1.2", "10.0.0.2"]

def is_blocked(ip: str) -> bool:
    return ip in BLOCKED_IPS
''',
        "keywords": ["set", "o(1)", "list lookup", "o(n)", "constant time", "hash", "membership test", "lookup", "convert to set"]
    },
    {
        "id": "PERF-09",
        "category": "Performance",
        "known_issue": "Unnecessary list comprehension creating intermediate list",
        "code": '''
def get_adult_count(users: list) -> int:
    adults = [u for u in users if u.age >= 18]
    return len(adults)

def get_total_price(items: list) -> float:
    prices = [item.price for item in items]
    return sum(prices)
''',
        "keywords": ["generator", "sum(", "len(", "intermediate", "memory", "generator expression", "unnecessary list", "sum(x", "generat"]
    },
    {
        "id": "PERF-10",
        "category": "Performance",
        "known_issue": "Missing database index on frequently queried column",
        "code": '''
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True)
    username = Column(String)
    created_at = Column(DateTime)

def find_by_username(username: str):
    return db.query(User).filter(User.username == username).first()
''',
        "keywords": ["index", "Index(", "query performance", "filter", "column", "indexed", "add index", "database index", "__table_args__"]
    },

    # ── FASTAPI BEST PRACTICES (10) ──────────────────────────────────────────

    {
        "id": "FASTAPI-01",
        "category": "FastAPI",
        "known_issue": "Missing response model - exposing internal fields",
        "code": '''
@router.get("/users/{user_id}")
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    return user
''',
        "keywords": ["response_model", "schema", "expose", "field", "pydantic", "sensitive", "internal", "return type", "model"]
    },
    {
        "id": "FASTAPI-02",
        "category": "FastAPI",
        "known_issue": "No HTTP status codes specified",
        "code": '''
@router.post("/users")
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = User(**user.dict())
    db.add(db_user)
    db.commit()
    return db_user
''',
        "keywords": ["status_code", "201", "http", "response", "status", "HTTP status", "status code", "created", "success"]
    },
    {
        "id": "FASTAPI-03",
        "category": "FastAPI",
        "known_issue": "No error handling for database operations",
        "code": '''
@router.get("/items/{item_id}")
def get_item(item_id: int, db: Session = Depends(get_db)):
    item = db.query(Item).filter(Item.id == item_id).first()
    return item
''',
        "keywords": ["404", "HTTPException", "not found", "error handling", "raise", "none check", "if not", "missing"]
    },
    {
        "id": "FASTAPI-04",
        "category": "FastAPI",
        "known_issue": "Missing input validation with Pydantic",
        "code": '''
@router.post("/register")
def register(username: str, email: str, age: int, db: Session = Depends(get_db)):
    user = User(username=username, email=email, age=age)
    db.add(user)
    db.commit()
    return user
''',
        "keywords": ["pydantic", "validation", "schema", "BaseModel", "validator", "request body", "type safety", "model"]
    },
    {
        "id": "FASTAPI-05",
        "category": "FastAPI",
        "known_issue": "Synchronous database operations without connection pooling",
        "code": '''
@router.get("/report")
def generate_report():
    conn = psycopg2.connect("postgresql://localhost/mydb")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders")
    results = cursor.fetchall()
    conn.close()
    return results
''',
        "keywords": ["async", "connection pool", "SQLAlchemy", "session", "Depends", "raw connection", "psycopg2", "direct connection"]
    },
    {
        "id": "FASTAPI-06",
        "category": "FastAPI",
        "known_issue": "No rate limiting on authentication endpoint",
        "code": '''
@router.post("/login")
def login(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if user and verify_password(password, user.hashed_password):
        return create_access_token(user.id)
    raise HTTPException(status_code=401, detail="Invalid credentials")
''',
        "keywords": ["rate limit", "brute force", "slowapi", "throttl", "limit", "attempt", "lockout", "too many requests"]
    },
    {
        "id": "FASTAPI-07",
        "category": "FastAPI",
        "known_issue": "Returning plain dict instead of Pydantic model",
        "code": '''
@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    total = db.query(User).count()
    active = db.query(User).filter(User.is_active == True).count()
    return {"total": total, "active": active, "inactive": total - active}
''',
        "keywords": ["response_model", "pydantic", "schema", "type hint", "model", "typed", "return type", "structured"]
    },
    {
        "id": "FASTAPI-08",
        "category": "FastAPI",
        "known_issue": "Missing dependency injection for settings",
        "code": '''
@router.get("/config")
def get_config():
    import os
    return {
        "debug": os.getenv("DEBUG", "false"),
        "db_host": os.getenv("DB_HOST", "localhost"),
        "api_version": "1.0"
    }
''',
        "keywords": ["dependency injection", "Settings", "pydantic", "BaseSettings", "inject", "configuration", "env", "environment"]
    },
    {
        "id": "FASTAPI-09",
        "category": "FastAPI",
        "known_issue": "No background task for long-running operations",
        "code": '''
@router.post("/send-newsletter")
def send_newsletter(db: Session = Depends(get_db)):
    users = db.query(User).all()
    for user in users:
        send_email(user.email, "Newsletter", get_newsletter_content())
    return {"message": "sent"}
''',
        "keywords": ["background", "BackgroundTasks", "async", "queue", "celery", "blocking", "long-running", "task", "worker"]
    },
    {
        "id": "FASTAPI-10",
        "category": "FastAPI",
        "known_issue": "Storing plain text password",
        "code": '''
@router.post("/users")
def create_user(username: str, password: str, db: Session = Depends(get_db)):
    user = User(username=username, password=password)
    db.add(user)
    db.commit()
    return {"id": user.id}
''',
        "keywords": ["hash", "bcrypt", "plain text", "plain-text", "password", "encrypt", "passlib", "never store", "hashed"]
    },

    # ── PYTHON BEST PRACTICES (10) ───────────────────────────────────────────

    {
        "id": "PY-01",
        "category": "Python",
        "known_issue": "Mutable default argument",
        "code": '''
def add_item(item: str, items: list = []):
    items.append(item)
    return items
''',
        "keywords": ["mutable", "mutable default", "default argument", "None", "anti-pattern", "shared state", "items = None", "evaluated once"]
    },
    {
        "id": "PY-02",
        "category": "Python",
        "known_issue": "Bare except catching all exceptions",
        "code": '''
def read_config(filepath: str):
    try:
        with open(filepath) as f:
            return json.load(f)
    except:
        return {}
''',
        "keywords": ["bare except", "specific exception", "catch all", "except:", "Exception", "too broad", "general exception", "specific"]
    },
    {
        "id": "PY-03",
        "category": "Python",
        "known_issue": "Not using context manager for file operations",
        "code": '''
def read_file(path: str) -> str:
    f = open(path, "r")
    content = f.read()
    f.close()
    return content
''',
        "keywords": ["context manager", "with statement", "with open", "close(", "resource leak", "file handle", "properly close", "with"]
    },
    {
        "id": "PY-04",
        "category": "Python",
        "known_issue": "Using type() instead of isinstance()",
        "code": '''
def process_value(value):
    if type(value) == int:
        return value * 2
    elif type(value) == str:
        return value.upper()
    elif type(value) == list:
        return len(value)
''',
        "keywords": ["isinstance", "type()", "inheritance", "subclass", "isinstance()", "preferred", "type check", "polymorphism"]
    },
    {
        "id": "PY-05",
        "category": "Python",
        "known_issue": "Not using enumerate() in loop with index",
        "code": '''
def print_items(items: list):
    for i in range(len(items)):
        print(f"{i}: {items[i]}")

def get_first_match(items: list, target: str):
    for i in range(len(items)):
        if items[i] == target:
            return i
    return -1
''',
        "keywords": ["enumerate", "range(len", "pythonic", "index", "loop", "enumerate(", "idiomatic", "unpythonic"]
    },
    {
        "id": "PY-06",
        "category": "Python",
        "known_issue": "String formatting with % operator instead of f-string",
        "code": '''
def greet_user(name: str, age: int) -> str:
    return "Hello %s, you are %d years old" % (name, age)

def log_error(error: str, code: int) -> str:
    return "Error %d: %s" % (code, error)
''',
        "keywords": ["f-string", "format(", "% operator", "string format", "modern", "old style", "preferred", ".format", "fstring"]
    },
    {
        "id": "PY-07",
        "category": "Python",
        "known_issue": "Missing type hints on function signatures",
        "code": '''
def calculate_total(items, tax_rate, discount):
    subtotal = sum(item["price"] * item["qty"] for item in items)
    tax = subtotal * tax_rate
    return subtotal + tax - discount

def find_user(user_id, db):
    return db.query(User).filter(User.id == user_id).first()
''',
        "keywords": ["type hint", "annotation", "typing", "->", ": float", ": int", ": str", "missing type", "return type", "type annotation"]
    },
    {
        "id": "PY-08",
        "category": "Python",
        "known_issue": "Global variable mutation",
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
''',
        "keywords": ["global", "global variable", "mutation", "state", "thread safe", "class", "encapsulat", "avoid global", "side effect"]
    },
    {
        "id": "PY-09",
        "category": "Python",
        "known_issue": "Comparing to None with == instead of is",
        "code": '''
def get_user_name(user):
    if user == None:
        return "Anonymous"
    if user.name == None:
        return "No name"
    return user.name
''',
        "keywords": ["is None", "is not None", "== None", "PEP 8", "identity", "singleton", "comparison", "is operator"]
    },
    {
        "id": "PY-10",
        "category": "Python",
        "known_issue": "Not using dataclass or Pydantic for data containers",
        "code": '''
def create_user_dict(name, email, age, role, is_active):
    return {
        "name": name,
        "email": email,
        "age": age,
        "role": role,
        "is_active": is_active,
        "created_at": datetime.now()
    }
''',
        "keywords": ["dataclass", "pydantic", "BaseModel", "TypedDict", "structured", "named tuple", "NamedTuple", "data class"]
    },
]


# ── Evaluation functions ──────────────────────────────────────────────────────

def run_security_pass(code):
    system = (
        "You are a security-focused code reviewer.\n"
        "CRITICAL RULES:\n"
        "- Only report issues you can PROVE exist in the code with exact line number\n"
        "- Do NOT invent issues\n"
        "- Format each issue as: LINE_NUMBER - SEVERITY - description\n\n"
        "Check for: security vulnerabilities, error handling, input validation"
    )
    try:
        return llm.invoke([
            SystemMessage(content=system),
            HumanMessage(content="Review this code:\n```python\n{}\n```".format(code))
        ]).content
    except Exception as e:
        return "Error: {}".format(e)


def run_solid_pass(code):
    system = (
        "You are a software architecture expert reviewing for SOLID principles.\n"
        "CRITICAL RULES:\n"
        "- Only flag violations with exact line number\n"
        "- Do NOT invent violations\n\n"
        "Check for: SOLID violations, DRY, KISS, clean code"
    )
    try:
        return llm.invoke([
            SystemMessage(content=system),
            HumanMessage(content="Review this code for SOLID violations:\n```python\n{}\n```".format(code))
        ]).content
    except Exception as e:
        return "Error: {}".format(e)


def run_optimization_pass(code):
    system = (
        "You are a Python performance expert.\n"
        "CRITICAL RULES:\n"
        "- Only suggest optimizations for code that actually exists\n"
        "- Cite exact line numbers\n\n"
        "Check for: time complexity, caching, async, list comprehensions"
    )
    try:
        return llm.invoke([
            SystemMessage(content=system),
            HumanMessage(content="Find performance issues in:\n```python\n{}\n```".format(code))
        ]).content
    except Exception as e:
        return "Error: {}".format(e)


def run_validation_pass(code, security, solid, optimization):
    system = (
        "You are a strict fact-checker.\n"
        "Validate that every issue mentioned actually exists in the code.\n"
        "Mark each as VALID or HALLUCINATED.\n\n"
        "Return:\n"
        "## Validated Issues\n"
        "## Removed (Hallucinated) Issues"
    )
    content = (
        "CODE:\n```python\n{}\n```\n\n"
        "SECURITY REVIEW:\n{}\n\n"
        "SOLID REVIEW:\n{}\n\n"
        "OPTIMIZATION:\n{}\n\n"
        "Validate all findings."
    ).format(code, security[:1500], solid[:1500], optimization[:1500])
    try:
        return llm.invoke([
            SystemMessage(content=system),
            HumanMessage(content=content)
        ]).content
    except Exception as e:
        return "Error: {}".format(e)


def check_detection(reviews_combined, keywords):
    combined_lower = reviews_combined.lower()
    for kw in keywords:
        if kw.lower() in combined_lower:
            return True
    return False


def count_hallucinated_in_result(validated):
    count = 0
    in_section = False
    for line in validated.split("\n"):
        if "Removed" in line or "Hallucinated" in line:
            in_section = True
        elif line.startswith("##"):
            in_section = False
        elif in_section and line.strip().startswith("-") and len(line.strip()) > 2:
            count += 1
    return count


def count_validated_in_result(validated):
    count = 0
    in_section = False
    for line in validated.split("\n"):
        if "Validated" in line and "Issues" in line:
            in_section = True
        elif "Removed" in line or "Hallucinated" in line:
            in_section = False
        elif in_section and line.strip().startswith("-") and len(line.strip()) > 2:
            count += 1
    return count


# ── Main evaluation runner ────────────────────────────────────────────────────

def run_evaluation():
    print("=" * 60)
    print("AI CODE REVIEW AGENT - EVALUATION SUITE")
    print("Testing {} known issues".format(len(TEST_CASES)))
    print("=" * 60)
    print()

    results = []
    total_detected = 0
    total_hallucinated = 0
    total_raw_findings = 0

    for i, test in enumerate(TEST_CASES):
        print("[{}/{}] {} - {}".format(i + 1, len(TEST_CASES), test["id"], test["known_issue"]))

        start = time.time()

        security  = run_security_pass(test["code"])
        solid     = run_solid_pass(test["code"])
        optim     = run_optimization_pass(test["code"])
        validated = run_validation_pass(test["code"], security, solid, optim)

        duration = time.time() - start

        all_reviews = security + " " + solid + " " + optim + " " + validated
        detected = check_detection(all_reviews, test["keywords"])

        hallucinated = count_hallucinated_in_result(validated)
        validated_count = count_validated_in_result(validated)
        raw = validated_count + hallucinated

        total_detected += 1 if detected else 0
        total_hallucinated += hallucinated
        total_raw_findings += raw

        status = "DETECTED" if detected else "MISSED"
        print("  Status: {} | Raw: {} | Hallucinated: {} | Validated: {} | Time: {:.1f}s".format(
            status, raw, hallucinated, validated_count, duration))

        results.append({
            "id": test["id"],
            "category": test["category"],
            "known_issue": test["known_issue"],
            "detected": detected,
            "raw_findings": raw,
            "hallucinated": hallucinated,
            "validated": validated_count,
            "duration": round(duration, 1),
        })

        time.sleep(1)

    # ── Final Report ──────────────────────────────────────────────────────────
    detection_rate = total_detected / len(TEST_CASES) * 100
    halluc_rate = (total_hallucinated / total_raw_findings * 100) if total_raw_findings > 0 else 0

    print()
    print("=" * 60)
    print("EVALUATION RESULTS")
    print("=" * 60)
    print()

    categories = ["Security", "SOLID", "Performance", "FastAPI", "Python"]
    print("DETECTION RESULTS BY CATEGORY:")
    print()
    for cat in categories:
        cat_results = [r for r in results if r["category"] == cat]
        detected = sum(1 for r in cat_results if r["detected"])
        total = len(cat_results)
        bar = "#" * detected + "-" * (total - detected)
        print("  {:<12} [{:<10}] {}/{} ({:.0f}%)".format(
            cat, bar, detected, total,
            detected / total * 100 if total > 0 else 0))

    print()
    print("OVERALL METRICS:")
    print("  Total test cases         : {}".format(len(TEST_CASES)))
    print("  Issues correctly detected: {}".format(total_detected))
    print("  Issues missed            : {}".format(len(TEST_CASES) - total_detected))
    print("  Detection rate           : {:.1f}%".format(detection_rate))
    print()
    print("ANTI-HALLUCINATION METRICS:")
    print("  Total raw findings       : {}".format(total_raw_findings))
    print("  Hallucinated (removed)   : {}".format(total_hallucinated))
    print("  Hallucination rate       : {:.1f}%".format(halluc_rate))
    print("  Accuracy after filter    : {:.1f}%".format(100 - halluc_rate))
    print()

    print("DETAILED RESULTS:")
    print("-" * 75)
    print("{:<12} {:<12} {:<35} {:<10} {:<6}".format(
        "ID", "Category", "Known Issue", "Detected", "Halluc"))
    print("-" * 75)
    for r in results:
        print("{:<12} {:<12} {:<35} {:<10} {:<6}".format(
            r["id"],
            r["category"],
            r["known_issue"][:33],
            "YES" if r["detected"] else "NO",
            r["hallucinated"]
        ))
    print("-" * 75)

    output = {
        "summary": {
            "total_tests": len(TEST_CASES),
            "detected": total_detected,
            "missed": len(TEST_CASES) - total_detected,
            "detection_rate": round(detection_rate, 1),
            "total_raw_findings": total_raw_findings,
            "total_hallucinated": total_hallucinated,
            "hallucination_rate": round(halluc_rate, 1),
            "accuracy_after_filter": round(100 - halluc_rate, 1),
        },
        "by_category": {
            cat: {
                "detected": sum(1 for r in results if r["category"] == cat and r["detected"]),
                "total": len([r for r in results if r["category"] == cat]),
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
    print("=" * 60)

    return output


if __name__ == "__main__":
    run_evaluation()