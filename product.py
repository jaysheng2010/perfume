from flask import Flask, jsonify, request, make_response, render_template_string
from flask_limiter import Limiter
from flask_cors import CORS
from sqlalchemy import create_engine, text
from argon2 import PasswordHasher
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import json
import secrets
from datetime import datetime, timedelta
import re
import requests as req
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from argon2.exceptions import VerifyMismatchError

# ------------------ CONFIG ------------------

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PHONE_RE = re.compile(r"^\+[1-9]\d{1,14}$")
PEPPER = "ert9iop"
SECRET_KEY = "super-secret-key"
TOKEN_SALT = "cart-salt"

# ------------------ HELPERS ------------------

def is_valid_email(email):
    return EMAIL_RE.match(email)

def is_valid_phone(phone):
    return PHONE_RE.match(phone)

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, salt_len=16)

def hash_password(password):
    return ph.hash(password + PEPPER)

def verify_password(hashed, password):
    return ph.verify(hashed, password + PEPPER)

serializer = URLSafeTimedSerializer(SECRET_KEY)
signed_signature = URLSafeTimedSerializer("A@123!23")

def generate_token_reset():
    return signed_signature.dumps(secrets.token_hex(16), salt="abc")

def check_token_reset(token_id: str):
    try:
        signed_signature.loads(token_id, salt="abc", max_age=3600)
        return True
    except (BadSignature, SignatureExpired):
        return False

def check_new_password(password):
    if (
        len(password) >= 12 and
        any(c.isupper() for c in password) and
        any(c.islower() for c in password) and
        any(c.isdigit() for c in password) and
        any(c in "!@#$%^&*()" for c in password)
    ):
        return True
    return False

def get_ip():
    return request.remote_addr

# ------------------ DATABASES ------------------

productdb = create_engine("mysql+pymysql://4J4VubRMtDYVKrk.root:UtLbWgr32k7ka8sW@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/perfume_product_db", pool_pre_ping=True)
clientdb = create_engine("mysql+pymysql://2p82bsJkP25gYSs.root:nRN29LbnYqSPat0f@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/client_db", pool_pre_ping=True)
orderdb = create_engine("mysql+pymysql://3ePjuz2Qec5Dphc.root:TFHd3bdTUar44EQL@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/order_db", pool_pre_ping=True)
cartdb = create_engine("mysql+pymysql://3SMehWwqfhnNVbU.root:kJSWY0ti6IeVBB4u@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/client_cart", pool_pre_ping=True)
tokendb = create_engine("mysql+pymysql://3SZzKdxQsk3bRh1.root:R9zhtb2WVtYbc1Ld@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/cart_token_db", pool_pre_ping=True)

uri = "mongodb+srv://ooijaysheng_db_user:L3KBj3bWQtmowQR4@reset-password-perfume.osyztke.mongodb.net/?appName=reset-password-perfume"
client = MongoClient(uri, server_api=ServerApi("1"))

db = client["reset-password-perfume"]
collections = db["token_reset_password_document"]
collections_post = db["token_reset_password_post"]

collections.create_index("token", unique=True)
collections_post.create_index("token_post", unique=True)
collections.create_index("expires_at", expireAfterSeconds=0)
collections_post.create_index("expires_at", expireAfterSeconds=0)

# ------------------ APP ------------------

app = Flask(__name__)
CORS(app, supports_credentials=True)
limiter = Limiter(app=app, key_func=get_ip)

# ------------------ LOGIN ------------------

@app.route("/login", methods=["POST"])
@limiter.limit("5/minute")
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"message": "Invalid credentials"}), 401

    email = data.get("email")
    password = data.get("password")

    with clientdb.connect() as conn:
        result = conn.execute(
            text("SELECT password, phone_number, date_joined FROM client_tbl WHERE email=:email"),
            {"email": email}
        ).fetchone()

    if not result:
        return jsonify({"message": "Invalid credentials"}), 401

    stored_password, phone, joined = result

    try:
        verify_password(stored_password, password)
    except VerifyMismatchError:
        return jsonify({"message": "Invalid credentials"}), 401

    cart_token = serializer.dumps({"email": email, "token": secrets.token_urlsafe(16)}, salt=TOKEN_SALT)

    with tokendb.begin() as conn:
        conn.execute(text("UPDATE cart_token_tbl SET token=:token WHERE email=:email"),
                     {"token": cart_token, "email": email})

    with cartdb.connect() as cart:
        cartdata = cart.execute(text("SELECT cart_items FROM cart_tbl WHERE email=:email"),
                                {"email": email}).fetchone()

    with orderdb.connect() as order:
        orderdata = order.execute(text("SELECT * FROM order_tbl WHERE email=:email"),
                                  {"email": email}).fetchall()
        orderdata = [dict(row._mapping) for row in orderdata]

    response = make_response(jsonify({
        "account": [email, phone, str(joined)],
        "orderdata": orderdata,
        "cartdata": cartdata[0] if cartdata else {},
        "message": "success"
    }))

    response.set_cookie("cart_token", cart_token, httponly=True, secure=True, samesite="None", max_age=3600)
    return response

# ------------------ REGISTER ------------------

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"message": "Invalid JSON"}), 400

    email = data["email"]
    password = data["password"]
    repeat = data["repeat_password"]
    phone = data["phone_no"]

    if password != repeat or not check_new_password(password):
        return jsonify({"message": "Password do not meet the criteria."}), 400

    if not is_valid_email(email) or not is_valid_phone(phone):
        return jsonify({"message": "Invalid email or phone"}), 400

    hashed = hash_password(password)
    now = datetime.now().strftime("%d/%m/%Y")

    with clientdb.begin() as conn:
        exists = conn.execute(text("SELECT 1 FROM client_tbl WHERE email=:email"), {"email": email}).fetchone()
        if exists:
            return jsonify({"message": "Invalid email or phone"}), 400

        conn.execute(text("""
            INSERT INTO client_tbl (email, password, phone_number, date_joined)
            VALUES (:email, :password, :phone, :date)
        """), {"email": email, "password": hashed, "phone": phone, "date": now})

    with cartdb.begin() as conn:
        conn.execute(text("INSERT INTO cart_tbl (email, cart_items) VALUES (:email, '{}')"),
                     {"email": email})

    cart_token = serializer.dumps({"email": email, "token": secrets.token_urlsafe(16)}, salt=TOKEN_SALT)

    with tokendb.begin() as conn:
        conn.execute(text("INSERT INTO cart_token_tbl (email, token) VALUES (:email, :token)"),
                     {"email": email, "token": cart_token})

    response = make_response(jsonify({"message": "success"}))
    response.set_cookie("cart_token", cart_token, httponly=True, secure=True, samesite="None", max_age=3600)
    return response

# ------------------ CART ------------------

@app.route("/cart", methods=["POST"])
def cart():
    token = request.cookies.get("cart_token")
    if not token:
        return jsonify({"message": "Missing token"}), 403

    try:
        payload = serializer.loads(token, salt=TOKEN_SALT, max_age=3600)
        email = payload["email"]

        with tokendb.connect() as conn:
            original_token = conn.execute(
                text("SELECT token FROM cart_token_tbl WHERE email=:email"),
                {"email": email}
            ).fetchone()

        if not original_token or original_token[0] != token:
            return jsonify({"message": "Invalid token"}), 403

    except (BadSignature, SignatureExpired):
        return jsonify({"message": "Invalid token"}), 403

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"message": "Invalid JSON"}), 400

    action = data["query"]
    product = data.get("product")
    quantity = int(data.get("quantity", 1))

    with productdb.connect() as con:
        pq = con.execute(text("SELECT quantity FROM product_tbl WHERE name=:name"),
                         {"name": product}).fetchone()
        if not pq:
            return jsonify({"message": "Product not found"}), 404
        product_qty = pq[0]

    with cartdb.begin() as conn:
        row = conn.execute(text("SELECT cart_items FROM cart_tbl WHERE email=:email"),
                           {"email": email}).fetchone()
        cart = json.loads(row[0]) if row and row[0] else {}

        if action == "insert":
            cart[product] = min(max(1, quantity), product_qty)

        elif action == "add":
            if cart.get(product, 0) + 1 > product_qty:
                return jsonify({"message": "Maximum products."})
            cart[product] = cart.get(product, 0) + 1

        elif action == "minus":
            if cart.get(product, 0) > 1:
                cart[product] -= 1
            else:
                cart.pop(product, None)

        elif action == "select":
            return jsonify(cart)

        elif action == "delete":
            cart.pop(product, None)

        conn.execute(text("UPDATE cart_tbl SET cart_items=:cart WHERE email=:email"),
                     {"cart": json.dumps(cart), "email": email})

    return jsonify({"message": "success"})

# ------------------ RESET PASSWORD ------------------

@app.route("/reset_id", methods=["POST"])
def get_reset_token():
    email = request.json.get("email")
    if not email:
        return {"message": "success"}

    token = generate_token_reset()
    collections.insert_one({
        "token": token,
        "email": email,
        "expires_at": datetime.utcnow() + timedelta(minutes=15)
    })

    req.post("", json={"email": email, "token": token})
    return {"message": "success"}

@app.route("/reset", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        token_post = request.form.get("token")
        email = request.form.get("email")
        password = request.form.get("password")

        if not check_new_password(password):
            return "Invalid password", 400

        user = collections_post.find_one({"token_post": token_post, "email_post": email})
        if not user:
            return "Invalid or expired token", 400

        with clientdb.begin() as conn:
            conn.execute(text("UPDATE client_tbl SET password=:p WHERE email=:e"),
                         {"p": hash_password(password), "e": email})

        collections_post.delete_one({"_id": user["_id"]})
        return "<h3>Password reset completed</h3>"

    token = request.args.get("token_id")
    if not check_token_reset(token):
        return "Invalid or expired token", 400

    user = collections.find_one({"token": token})
    if not user:
        return "Invalid or expired token", 400

    new_token = secrets.token_urlsafe(32)
    collections_post.insert_one({
        "token_post": new_token,
        "email_post": user["email"],
        "expires_at": datetime.utcnow() + timedelta(minutes=15)
    })
    collections.delete_one({"_id": user["_id"]})

    return render_template_string("""
     <div id="reset_password_container">
    <div>
        <h1>Reset password</h1>
        <p>Enter your new password.</p>
        <form method="POST">
          <label for="">Password</label>
          <br>
          <input type="password" placeholder="New password" name="password">
          <input type="text" name="email" value={{email}} hidden>
          <input type="text" name="token" value={{token}} hidden>
          <br>
          <button id="send_button" type="submit">Reset</button>
        </form>
    </div>
</div>

<style>
    #reset_password_container {
        display: flex;
        align-items: center;
        justify-content: center;
        width: 100%;
        height: 100%;
        background: transparent;
        position: absolute;
        top: 0;
        left: 0;
    }

    #reset_password_container>div {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 10px;
        border: 1px solid rgb(195, 197,200);
        border-radius: 5px;
        width: 80%;
        padding: 10px;
    }

    label {
        color: rgb(195, 197,200);
        font-size: 15px;
    }

    #send_button {
        background-color: blue;
        color: white;
        font-size: 17px;
        padding: 10px;
    }

    #close_button {
        background-color: red;
        color: white;
        font-size: 20px;
        padding: 10px;
    }

    input {
        padding: 8px;
        border: 1px solid rgb(195, 197,200);
        border-radius: 5px;
    }
</style>
   """, email=user["email"], token=new_token)

# ------------------ DELETE ACCOUNT ------------------

@app.route("/delete", methods=["POST"])
def delete_account():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    with clientdb.connect() as conn:
        original = conn.execute(
            text("SELECT password FROM client_tbl WHERE email=:email"),
            {"email": email}
        ).fetchone()

    if not original:
        return jsonify({"message": "incorrect password"}), 401

    try:
        verify_password(original[0], password)
    except VerifyMismatchError:
        return jsonify({"message": "incorrect password"}), 401

    with clientdb.begin() as conn:
        conn.execute(text("DELETE FROM client_tbl WHERE email=:email"), {"email": email})
    with tokendb.begin() as conn:
        conn.execute(text("DELETE FROM cart_token_tbl WHERE email=:email"), {"email": email})
    with cartdb.begin() as conn:
        conn.execute(text("DELETE FROM cart_tbl WHERE email=:email"), {"email": email})

    return jsonify({"message": "success"})

