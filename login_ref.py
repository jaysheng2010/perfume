from flask import Flask, render_template_string, jsonify, request, make_response
from flask_cors import CORS
from flask_limiter import Limiter
from datetime import datetime, timedelta
import secrets
import os
import json
import random
import requests as req
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import threading
from argon2 import PasswordHasher 
from sqlalchemy import create_engine, text
#from libsql import LibSQLClient
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import time
import pymysql

conn = pymysql.connect(
    host = "gateway01.ap-southeast-1.prod.aws.tidbcloud.com",
    port = 4000,
    user = "4J4VubRMtDYVKrk.root",
    password = "wG0Spu5csxaT3smS",
    database = "perfume_product_db",
    ssl={
        "ca": "/etc/ssl/cert.pem"
    }
)

productdb = conn.cursor()

conn2 = pymysql.connect(
    host="gateway01.us-west-2.prod.aws.tidbcloud.com",
    port=4000,
    user="2p82bsJkP25gYSs.root",
    password="gI0fwNVp3zx4WoIc",
    database="clientdb",
    ssl={
        "ca": "/etc/ssl/cert.pem"
    }
)

clientdb = conn2.cursor()

conn3 = pymysql.connect(
    host = "gateway01.ap-southeast-1.prod.aws.tidbcloud.com",
    port = 4000,
    user = "bi4KAtt6wF3FLtR.root",
    password = "l6kNs6Rjs18FyvMD",
    database = "orderdb",
    ssl={
        "ca": "/etc/ssl/cert.pem"
    }
)

orderdb = conn3.cursor()

conn4 = pymysql.connect(
    host = "gateway01.ap-southeast-1.prod.aws.tidbcloud.com",
    port = 4000,
    user = "3SZzKdxQsk3bRh1.root",
    password = "DyWkHIPgRjK9a2qa",
    database = "cart_token_db",
    ssl={
        "ca": "/etc/ssl/cert.pem"
    }
)

cart_token_db = conn4.cursor()

conn5 = pymysql.connect(
    host = "gateway01.ap-southeast-1.prod.aws.tidbcloud.com",
    port = 4000,
    user = "3SZzKdxQsk3bRh1.root",
    password = "DyWkHIPgRjK9a2qa",
    database = "cart_token_db",
    ssl={
        "ca": "/etc/ssl/cert.pem"
    }
)
cart_1 = conn5.cursor()

conn6 = pymysql.connect(
    host = "gateway01.ap-southeast-1.prod.aws.tidbcloud.com",
    port = 4000,
    user = "3SZzKdxQsk3bRh1.root",
    password = "DyWkHIPgRjK9a2qa",
    database = "cart_token_db",
    ssl={
        "ca": "/etc/ssl/cert.pem"
    }
)
cart_2 = conn6.cursor()

uri = "mongodb+srv://ooijaysheng_db_user:L3KBj3bWQtmowQR4@reset-password-perfume.osyztke.mongodb.net/?appName=reset-password-perfume"
uri_post = ""
# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'))
client_post = MongoClient(uri_post, server_api=ServerApi('1'))
# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    client_post.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)

db = client["reset-password-perfume"]
collections = db["token_reset_password_document"]

db_post = client_post[""]
collections_post = db_post[""]

"""
# cart_token database
client_turso_cart = libsql_client.create_client(
    url=os.environ["TURSO_DATABASE_URL"],
    auth_token=os.environ["TURSO_AUTH_TOKEN"]
)


product_db = create_engine(
   "pymysql+mysql://4J4VubRMtDYVKrk.root:OFOP2eUkZFWs0rvM@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/perfume_product_db",
    connect_args={
        "ssl": {"ca": "/etc/ssl/cert.pem"}
    },
    pool_size=10,
    max_overflow=20,
    pool_recycle=1800,
    pool_pre_ping=True,
)

cart_one_db = create_engine(
   "pymysql+mysql://3SMehWwqfhnNVbU.root:yHRGRQPjr0UniG0F@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/client_cart",
    connect_args={
        "ssl": {"ca": "/etc/ssl/cert.pem"}
    },
    pool_size=10,
    max_overflow=20,
    pool_recycle=1800,
    pool_pre_ping=True,
    )

# password reset email token

# cart table
engine = LibSQLClient(url="libsql://cart-token-db-perfume.aws-us-east-1.turso.io", auth="eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJzNGtaX1BRZEVmQ244alloclBoc3hRIn0.RKRCegnd9Dr4DTNPVC0rVZ0qTktWEBpKyF7tNdf_x9HNI5HmlMAnE3muTaf6nLzBskOXRxuyhk6G0vuxcMvwBw")

engine_cart_1 = 

PEPPER = os.environ["PEPPER"]
"""
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64MB
    parallelism=4,
    salt_len=16
)

def hash_password(password):
    return ph.hash(password + PEPPER)

def verify_password(hashed_password, password):
    return ph.verity(hashed_password, password + PEPPER)

def find_password(email):
    clientdb.execute("SELECT password FROM client_tbl WHERE email = ?", (email))
    result = clientdb.fetchone[0]
    return result

signed_signature = URLSafeTimedSerializer("")
def generate_token_reset():
   token_id = secrets.token_hex(16)
   return signed_signature.dumps(token_id, salt="", max_age=3600)

def check_token_reset(token_id: str):
   try: 
      signed_signature.loads(token_id, salt="")
      return True
   except BadSignature:
      return False
   
def clean_cart_id(interval_seconds=3600):
   while True:
     now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
     cart_token_db.execute("DELETE FROM cart_token_tbl WHERE expires_at <= ?", (now))
     time.sleep(interval_seconds)  
threading.Thread(target=clean_cart_id, daemon=True).start()

def check_before(product_name, quantity):
   productdb.execute("SELECT quantity FROM product_tbl WHERE id = ?", product_name)
   result = productdb.fetchone()
   if quantity > result[0]:
      return False
   else: 
      return True
   
   
def update(cursor, cart_json, email):
   cursor.execute("UPDATE cart_tbl SET cart_items = ? WHERE email = ?", (cart_json, email))

def select(cursor, cart_json, email):
   cursor.execute("SELECT cart_items FROM cart_tbl WHERE email = ?", (cart_json, email))
   return cursor.fetchone()[0]

   
PEPPER = generate_token_reset()

app = Flask(__name__)

@app.route("/register")
def register():
    try:
      information = request.json
      email = information["email"]
      password = information["password"]
      phone_no = information["phone_no"]
      cart_cluster = random.choice([cart_1, cart_2])
      hashed = hash_password(password)
      clientdb.execute("INSERT INTO client_tbl (email, password, phone_number, date_joined, cart_cluster) VALUES (%s,%s,%s, NOW(), %s)", (email, hashed, phone_no, cart_cluster))
      match cart_cluster:
         case cart_1:
            cart_1.execute("INSERT INTO cart_tbl (email) VALUES (?)", (email))
         case cart_2:
            cart_2.execute("INSERT INTO cart_tbl (email) VALUES (?)", (email))
    
      return True
    except:
       return False

@app.route("/login")
def login():
    login_details = request.json()
    login_email = login_details.get("email")
    login_password = login_details.get("password")
    try: 
      clientdb.execute("SELECT password from client_tbl WHERE email = ?", (login_email))
      stored_password = clientdb.fetchone[0]
    except:
        return "No email found"
    verification = verify_password(stored_password, login_password)
    if (verification):
        clientdb.execute("SELECT phone_number, date_joined FROM client_tbl WHERE email = ?", (login_email))
        result = clientdb.fetchone()
        orderdb.execute("SELECT order_id, order_items FROM order_tbl WHERE email = ?", (login_email))
        order = orderdb.fetchone()
        signed_cart_signature = URLSafeTimedSerializer()
        cart_id = signed_cart_signature.dumps(secrets.token_urlsafe(20), salt="", max_age=36000)
        expires_at = (datetime.utcnow() + timedelta(minutes=60)).strftime("%Y-%m-%d %H:%M:%S")
        cart_token_db.execute("INSERT INTO cart_token_tbl (email, cart_token, expires_at) VALUES (?,?,?)", (login_email,cart_id,expires_at))
        response = make_response(jsonify({"client_details": result, "client_order": order}))
        response.set_cookie("cart_token", cart_id, httponly=True, samesite="None", max_age=3600, secure=True)
        return response
    else: 
        return jsonify({"login_success": "failed"})
    
@app.route("/reset_id")
def get_reset_token():
    email = request.json["email"]
    token = generate_token_reset()
    collections.insert_one({
      {
          "token" : token,
          "email": email
      }
    })
    response = req.post("", {"", token})
    return "Success"
    
@app.route("/reset", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        token_post = request.form.get("token")
        if check_token_reset(token_post):
          new_password = request.form.get("new_password")
          email = request.form.get("email")
          user = collections_post.find_one({"token_post": token, "email_post": email})
          clientdb.execute("UPDATE client_tbl SET password = ? WHERE email = ?", (new_password, user["email_post"]))
          return render_template_string("")
    token = request.args.get("token_id")
    if check_token_reset(token):
        try: 
          user = collections.find_one({"token": token})
        except:
           return "No user found"
        signed_post_signature = URLSafeTimedSerializer()
        email_client = user["email"]
        new_token = signed_post_signature.dumps(secrets.token_urlsafe(20), salt="", max_age=3600)
        collections_post.insert_one({
           "token_post": new_token,
           "email_post": email_client
        })
        return render_template_string("", token=new_token, email=email_client)
    

@app.route("cart")
def cart():
   cart_request = request.json
   email = cart_request["email"]
   query = cart_request["query"]
   product = cart_request["product"]
   token_arrived = request.cookies.get("cart_token")
   try: 
     cart_token_db.execute("SELECT cart_token FROM cart_token_tbl WHERE email = ?", (email))
     real_token = cart_token_db.fetchone()[0]
   except Exception as e:
      print(e)
   if real_token != token_arrived:
      return "Tampered"
   else:
    clientdb.execute("SELECT cart_cluster FROM client_tbl WHERE email = ?", email)
    cluster = clientdb.fetchone()[0]
    cart_dict = json.loads(select(cluster, email))
    
    match query:
       case "insert":
          quantity = cart_request["quantity"]
          cart_dict[product] = quantity
       case "add":
          cart_dict[product] = cart_dict.get(product, 0) + 1
       case "minus":
          cart_dict[product] = cart_dict.get(product) - 1
       case "delete":
          del cart_dict[product]

    update(cluster, json.dumps(cart_dict), email)
          
          
          






{
   "cart_items": {
      "name": 2,
      "name": 2,
      "name": 2,
   }
}
