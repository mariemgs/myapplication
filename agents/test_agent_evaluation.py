"""
AI Code Review Agent - Evaluation Test Suite
Tests 20 known issues across Security, SOLID, Performance categories
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

# ── 20 Test Cases with known issues ──────────────────────────────────────────

TEST_CASES = [

    # ── SECURITY ISSUES (5) ──────────────────────────────────────────────────

    {
        "id": "SEC-01",
        "category": "Security",
        "known_issue": "SQL Injection vulnerability",
        "code": '''
def get_user(user_id: str):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
''',
        "keywords": ["sql injection", "injection", "user_id", "concatenat"]
    },
    {
        "id": "SEC-02",
        "category": "Security",
        "known_issue": "Hardcoded secret/password",
        "code": '''
DATABASE_PASSWORD = "admin123"
SECRET_KEY = "mysupersecretkey"
API_TOKEN = "ghp_abc123realtoken"
''',
        "keywords": ["hardcoded", "secret", "password", "credential", "token"]
    },
    {
        "id": "SEC-03",
        "category": "Security",
        "known_issue": "Command injection via os.system",
        "code": '''
def run_command(user_input: str):
    os.system(user_input)
    subprocess.call(user_input, shell=True)
''',
        "keywords": ["command injection", "os.system", "shell=true", "injection"]
    },
    {
        "id": "SEC-04",
        "category": "Security",
        "known_issue": "Missing authentication check on sensitive endpoint",
        "code": '''
@router.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    db.delete(user)
    db.commit()
    return {"message": "deleted"}
''',
        "keywords": ["authentication", "authorization", "current_user", "permission", "auth"]
    },
    {
        "id": "SEC-05",
        "category": "Security",
        "known_issue": "Insecure random number generation for security token",
        "code": '''
import random

def generate_token():
    return str(random.randint(100000, 999999))

def reset_password(email: str):
    token = generate_token()
    send_email(email, token)
''',
        "keywords": ["random", "insecure", "secrets", "cryptograph", "predictable"]
    },

    # ── SOLID VIOLATIONS (5) ─────────────────────────────────────────────────

    {
        "id": "SOLID-01",
        "category": "SOLID",
        "known_issue": "Single Responsibility Principle violation - God class",
        "code": '''
class UserManager:
    def create_user(self, name, email, password):
        # creates user in db
        pass

    def send_welcome_email(self, email):
        # sends email via SMTP
        pass

    def generate_pdf_report(self, user_id):
        # generates PDF
        pass

    def connect_to_database(self):
        # manages DB connection
        pass

    def log_to_file(self, message):
        # handles logging
        pass

    def validate_credit_card(self, card_number):
        # validates payment
        pass
''',
        "keywords": ["single responsibility", "srp", "god class", "multiple responsibilities", "one class"]
    },
    {
        "id": "SOLID-02",
        "category": "SOLID",
        "known_issue": "Open/Closed Principle violation - modifying existing class for new behavior",
        "code": '''
class PaymentProcessor:
    def process(self, payment_type: str, amount: float):
        if payment_type == "credit_card":
            # process credit card
            pass
        elif payment_type == "paypal":
            # process paypal
            pass
        elif payment_type == "bitcoin":
            # process bitcoin
            pass
        # every new payment type requires modifying this class
''',
        "keywords": ["open/closed", "ocp", "if/elif", "extension", "modification", "polymorphism"]
    },
    {
        "id": "SOLID-03",
        "category": "SOLID",
        "known_issue": "Dependency Inversion Principle violation - depending on concrete class",
        "code": '''
class OrderService:
    def __init__(self):
        self.db = MySQLDatabase()  # concrete dependency
        self.emailer = GmailEmailer()  # concrete dependency

    def place_order(self, order):
        self.db.save(order)
        self.emailer.send_confirmation(order)
''',
        "keywords": ["dependency inversion", "dip", "concrete", "abstraction", "interface", "inject"]
    },
    {
        "id": "SOLID-04",
        "category": "SOLID",
        "known_issue": "DRY violation - duplicated code",
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
        "keywords": ["dry", "duplicate", "repeated", "extract", "reuse"]
    },
    {
        "id": "SOLID-05",
        "category": "SOLID",
        "known_issue": "Interface Segregation / function doing too many things",
        "code": '''
def process_user_data(user_id, update_profile=False,
                      send_email=False, generate_report=False,
                      delete_account=False, export_data=False):
    user = get_user(user_id)
    if update_profile:
        update_user_profile(user)
    if send_email:
        send_notification_email(user)
    if generate_report:
        create_user_report(user)
    if delete_account:
        delete_user_account(user)
    if export_data:
        export_user_data(user)
''',
        "keywords": ["interface segregation", "too many", "boolean flag", "single function", "responsibility"]
    },

    # ── PERFORMANCE ISSUES (5) ───────────────────────────────────────────────

    {
        "id": "PERF-01",
        "category": "Performance",
        "known_issue": "O(n²) nested loop - quadratic complexity",
        "code": '''
def find_duplicates(items: list):
    duplicates = []
    for i in range(len(items)):
        for j in range(len(items)):
            if i != j and items[i] == items[j]:
                duplicates.append(items[i])
    return duplicates
''',
        "keywords": ["o(n", "quadratic", "nested loop", "complexity", "n^2", "n²"]
    },
    {
        "id": "PERF-02",
        "category": "Performance",
        "known_issue": "N+1 query problem in database loop",
        "code": '''
def get_all_user_orders():
    users = db.query(User).all()
    result = []
    for user in users:
        orders = db.query(Order).filter(Order.user_id == user.id).all()
        result.append({"user": user, "orders": orders})
    return result
''',
        "keywords": ["n+1", "query", "loop", "join", "eager loading", "batch"]
    },
    {
        "id": "PERF-03",
        "category": "Performance",
        "known_issue": "Blocking I/O without async in FastAPI endpoint",
        "code": '''
@router.get("/data")
def fetch_external_data():
    import requests
    response = requests.get("https://api.external.com/data")
    time.sleep(2)
    return response.json()
''',
        "keywords": ["async", "await", "blocking", "asyncio", "httpx", "synchronous"]
    },
    {
        "id": "PERF-04",
        "category": "Performance",
        "known_issue": "Repeated expensive computation without caching",
        "code": '''
def get_fibonacci(n: int) -> int:
    if n <= 1:
        return n
    return get_fibonacci(n - 1) + get_fibonacci(n - 2)

@router.get("/fib/{n}")
def fibonacci_endpoint(n: int):
    return {"result": get_fibonacci(n)}
''',
        "keywords": ["cache", "lru_cache", "memoiz", "recursive", "exponential", "redundant"]
    },
    {
        "id": "PERF-05",
        "category": "Performance",
        "known_issue": "Inefficient list building with + operator in loop",
        "code": '''
def build_report(items):
    report = ""
    for item in items:
        report = report + str(item) + ", "
    return report

def get_ids(users):
    ids = []
    for user in users:
        ids = ids + [user.id]
    return ids
''',
        "keywords": ["concatenat", "append", "join", "list comprehension", "inefficient", "string"]
    },

    # ── COMBINED / MIXED ISSUES (5) ──────────────────────────────────────────

    {
        "id": "MIX-01",
        "category": "Mixed",
        "known_issue": "No error handling + missing input validation",
        "code": '''
@router.post("/transfer")
def transfer_money(from_id: int, to_id: int, amount: float):
    sender = db.query(Account).filter(Account.id == from_id).first()
    receiver = db.query(Account).filter(Account.id == to_id).first()
    sender.balance -= amount
    receiver.balance += amount
    db.commit()
    return {"status": "transferred"}
''',
        "keywords": ["error handling", "validation", "try", "except", "negative", "none check", "balance"]
    },
    {
        "id": "MIX-02",
        "category": "Mixed",
        "known_issue": "Hardcoded credentials + no environment variables",
        "code": '''
def connect_to_database():
    return psycopg2.connect(
        host="localhost",
        database="production_db",
        user="admin",
        password="P@ssw0rd123!"
    )
''',
        "keywords": ["hardcoded", "environment", "credential", "password", "os.environ", "secret"]
    },
    {
        "id": "MIX-03",
        "category": "Mixed",
        "known_issue": "Unrestricted file upload - path traversal vulnerability",
        "code": '''
@router.post("/upload")
async def upload_file(file: UploadFile):
    file_path = f"uploads/{file.filename}"
    with open(file_path, "wb") as f:
        content = await file.read()
        f.write(content)
    return {"path": file_path}
''',
        "keywords": ["path traversal", "filename", "sanitiz", "upload", "directory", "../"]
    },
    {
        "id": "MIX-04",
        "category": "Mixed",
        "known_issue": "Mutable default argument - Python anti-pattern",
        "code": '''
def add_item(item: str, items: list = []):
    items.append(item)
    return items

def process_tags(tag: str, tags: dict = {}):
    tags[tag] = True
    return tags
''',
        "keywords": ["mutable", "default argument", "list", "dict", "anti-pattern", "shared state"]
    },
    {
        "id": "MIX-05",
        "category": "Mixed",
        "known_issue": "Missing pagination - loading all records",
        "code": '''
@router.get("/users")
def get_all_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return users

@router.get("/logs")
def get_all_logs(db: Session = Depends(get_db)):
    logs = db.query(Log).all()
    return logs
''',
        "keywords": ["pagination", "limit", "offset", "all()", "performance", "memory"]
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
    """Check if any keyword appears in the combined review output."""
    combined_lower = reviews_combined.lower()
    for kw in keywords:
        if kw.lower() in combined_lower:
            return True
    return False


def count_hallucinated_in_result(validated):
    """Count how many items were marked as hallucinated."""
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
    """Count validated issues."""
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

        # Run all 4 passes
        security  = run_security_pass(test["code"])
        solid     = run_solid_pass(test["code"])
        optim     = run_optimization_pass(test["code"])
        validated = run_validation_pass(test["code"], security, solid, optim)

        duration = time.time() - start

        # Check detection
        all_reviews = security + " " + solid + " " + optim + " " + validated
        detected = check_detection(all_reviews, test["keywords"])

        # Count findings
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
            "security_review": security[:300],
            "validated_report": validated[:300],
        })

        # Small delay to avoid rate limiting
        time.sleep(1)

    # ── Final Report ──────────────────────────────────────────────────────────
    detection_rate = total_detected / len(TEST_CASES) * 100
    halluc_rate = (total_hallucinated / total_raw_findings * 100) if total_raw_findings > 0 else 0

    print()
    print("=" * 60)
    print("EVALUATION RESULTS")
    print("=" * 60)
    print()
    print("DETECTION RESULTS BY CATEGORY:")
    print()

    categories = ["Security", "SOLID", "Performance", "Mixed"]
    for cat in categories:
        cat_results = [r for r in results if r["category"] == cat]
        detected = sum(1 for r in cat_results if r["detected"])
        print("  {} : {}/{} detected ({:.0f}%)".format(
            cat, detected, len(cat_results),
            detected / len(cat_results) * 100 if cat_results else 0))

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

    # Detailed results table
    print("DETAILED RESULTS:")
    print("-" * 80)
    print("{:<10} {:<12} {:<40} {:<10} {:<8}".format(
        "ID", "Category", "Known Issue", "Detected", "Halluc."))
    print("-" * 80)
    for r in results:
        print("{:<10} {:<12} {:<40} {:<10} {:<8}".format(
            r["id"],
            r["category"],
            r["known_issue"][:38],
            "YES" if r["detected"] else "NO",
            r["hallucinated"]
        ))
    print("-" * 80)

    # Save results to JSON
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