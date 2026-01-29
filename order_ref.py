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

"""
engine = create_engine(
   "mysql+pymysql://user:password@host:4000/dbname",
    connect_args={
        "ssl": {"ca": "/path/to/ca.pem"}
    },
    pool_size=10,
    max_overflow=20,
    pool_recycle=1800,
    pool_pre_ping=True,
    )

order_turso = LibSQLClient(url="libsql://client-order-db-jasonooi.aws-us-west-2.turso.io", auth="eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3Njg3Mjc2NzgsImlkIjoiYjMyNTZiNzMtZDFhOS00YWZmLThjYWItNWZjZGI1ZjYxOGVjIiwicmlkIjoiNTdmYjEyNWYtZDk2OC00NjZkLWFkOGYtZDcyNTAwNjBhM2M2In0.WD5wLnFQElne_x1EZ1mdGEFNq05nhYQwLwtpcfnzOlVT9p6RmumoBAyNK96bhSa471O6KEEedrguxYSQGWbLCA")
"""

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
    user = "bi4KAtt6wF3FLtR.root",
    password = "l6kNs6Rjs18FyvMD",
    database = "orderdb",
    ssl={
        "ca": "/etc/ssl/cert.pem"
    }
)
order_cache = conn4.cursor()

def select(query, value):
   with engine.connect() as conn:
      rows = conn.execute(text(query), value)
      return list(rows)
   
def update(query, value):
   with engine.begin() as conn:
       conn.execute(text(query), value)
   
def insert(query, value):
   with engine.begin() as conn:
       conn.execute(text(query), value)
   
def delete(query, value):
   with engine.begin() as conn:
       conn.execute(text(query), value)

signed_signature = URLSafeTimedSerializer("")
def generate_order_id(order_id):
   return signed_signature.dumps(order_id, salt="")

def check_order_id(order_id: str, email):
   orderdb.execute("SELECT order_id FROM order_tbl WHERE email = ?", (email))
   result = orderdb.fetchall()
   order_ids = [row[0] for row in result]
   if order_id in order_ids:
      return True
   else:
      return False
   
def get_ip():
   if "X-Forwarded-For" in request.headers:
      return request.headers["X-Forwarded-For"].split(",")[0].strip()
   else:
      return request.remote_addr

app = Flask(__name__)

CORS(app, allow_headers=["Content-Type", "Authorisation"], methods=["GET", "POST", "OPTIONS"], origins=[])
limiter = Limiter(app=app, key_func=get_ip)

@limiter.limit()
@app.route("/order")
def order():
    order_data = request.json

    for key, value in order_data["order"].items():
       order_data["order"][key] = bleach.clean(value, strip=False)
    
    address = order_data.get("delivery")
    email = order_data.get("email")
    phone_no = order_data.get("phone_no")
    order_id = secrets.token_urlsafe(20)
    ordered_list = order_data["order"]

    orderdb.execute("INSERT INTO order_tbl VALUES ()", [order_id, email, phone_no, order_items, address])

    for x in ordered_list:
         productdb.execute("SELECT quantity FROM product_tbl WHERE name = ?", x[0])
         quantity = productdb.fetchone()
         quantity_left = quantity[0] - int(x[1])
         update("UPDATE product_tbl SET quantity = ? WHERE name = ?", [quantity_left, x[0]])
    return "Success"

@app.route("/cancel_order")
def cancel_order():
   cancel_orderdata = request.json
   email = cancel_orderdata["email"]
   order_id = cancel_orderdata["order_id"]
   if check_order_id(order_id, email):
      client_order = order_turso.execute("SELECT order_items FROM order_tbl WHERE email = ?", [email])
      client_order = dict(client_order.rows[0])
      order_turso.execute("DELETE FROM order_tbl WHERE order_id = ? AND email = ?", [order_id, email])
      with engine.connect() as tidb:
        for key, value in client_order.items():
           tidb.execute("SELECT quantity FROM product_tbl WHERE name = ?", key)
           quantity = tidb.fetchone()
           quantity_left = quantity[0] + int(value)
           update("UPDATE product_tbl SET quantity = ? WHERE name = ?", [quantity_left, key])
      return "Success"
   else:
      return "Order ID been tampered"
   
@app.route("")
def order_summary():
   orderdata = request.json()
   order_cache_list = []
   for key, value in orderdata["order"].items():
       orderdata["order"][key] = bleach.clean(value, strip=False)
       productdb.execute("SELECT quantity FROM product_tbl WERE name = ?", (key))
       quantity = productdb.fetchone()[0]
       if quantity < value:
          orderdata["order"][key] = quantity
       order_cache_list.append([key, orderdata["order"][key]])

   return render_template_string()
   



   
"""
   {
      "email": email,
      "order_id": ""
   }

   {
     "":
   }


   {
      "order": [
         {"name": 1}
      ],
      "delivery": {
         "address": "",
         "postal_code": "",
         "city": "",
         "country": ""
      }
   }
   """
