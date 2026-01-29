from flask import Flask, render_template_string, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_talisman import Talisman
import os
import random
import bleach
import secrets 
from itsdangerous import URLSafeTimedSerializer, BadSignature
from sqlalchemy import create_engine, text
import pymysql
import threading
from argon2 import PasswordHasher 

import re

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

def is_valid_email(email):
    return EMAIL_RE.match(email) is not None



productdb = create_engine(
   "mysql+pymysql://4J4VubRMtDYVKrk.root:UtLbWgr32k7ka8sW@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/perfume_product_db",
    connect_args={
        "ssl": {"ca": "/etc/ssl/cert.pem"}
    },
    pool_size=10,
    max_overflow=20,
    pool_recycle=1800,
    pool_pre_ping=True,
)


clientdb = create_engine(
   "mysql+pymysql://2p82bsJkP25gYSs.root:gI0fwNVp3zx4WoIc@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/client_db",
    connect_args={
        "ssl": {"ca": "/etc/ssl/cert.pem"}
    },
    pool_size=10,
    max_overflow=20,
    pool_recycle=1800,
    pool_pre_ping=True,
)


ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64MB
    parallelism=4,
    salt_len=16
)

def hash_password(password):
    return ph.hash(password + PEPPER)

def verify_password(hashed_password, password):
    return ph.verify(hashed_password, password + PEPPER)

def find_password(email):
    clientdb.execute("SELECT password FROM client_tbl WHERE email = ?", (email))
    result = clientdb.fetchone()[0]
    return result


app = Flask(__name__)

@app.route("/login")
def login():
    login_details = request.json
    login_email = login_details.get("email")
    login_password = login_details.get("password")
    try: 
      clientdb.execute("SELECT password from client_tbl WHERE email = ?", (login_email))
      stored_password = clientdb.fetchone()[0]
    except Exception:
        return "No email found"
    try:
       verify_password(stored_password, login_password)
       verification = True
    except:
      verification = False

    if (verification):
        clientdb.execute(text("SELECT phone_number, date_joined FROM client_tbl WHERE email = :login_email"), {"login_email":login_email})
        result = clientdb.fetchone()
        orderdb.execute(text("SELECT order_id, order_items FROM order_tbl WHERE email = :login_email"), {"login_email":login_email})
        order = orderdb.fetchone()
        signed_cart_signature = URLSafeTimedSerializer()
        cart_id = signed_cart_signature.dumps(secrets.token_urlsafe(20), salt="", max_age=36000)
        expires_at = (datetime.utcnow() + timedelta(minutes=60)).strftime("%Y-%m-%d %H:%M:%S")
        cart_token_db.execute(text("INSERT INTO cart_token_tbl (email, cart_token, expires_at) VALUES (:login_email,:cart_id,:expires_at)"), {"login_email":login_email,"cart_id":cart_id,"expires_at":expires_at})
        cartdb.execute(text("SELECT cart_items FROM cart_tbl WHERE email = :login_email"), {"login_email":login_email})
        cartdata = cartdb.fetchone()
        response = make_response(jsonify({"client_details": result, "client_order": order, "cart_data": cartdata, "message": "success"}))
        response.set_cookie("cart_token", cart_id, httponly=True, samesite="None", max_age=3600, secure=True)
        return response
    else: 
        return jsonify({"message": "failed"})
