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

signed_signature = URLSafeTimedSerializer("")
def generate_token():
   token_id = secrets.token_hex(16)
   return signed_signature.dumps(token_id, salt="", max_age=3600)

def check_token(token_id: str):
   try: 
      signed_signature.loads(token_id, salt="")
      return True
   except BadSignature:
      return False
   

def check():
    productdb.execute("SELECT token FROM product_tbl")
    result = productdb.fetchall()
    for x in result:
        if not (check_token(x)):
            productdb.execute("SELECT cached_items FROM product_tbl WHERE token = ?", (x))
            order_json = productdb.fetchone()[0]
            order_dict = dict(order_json)

            for y in order_dict["order"]:
                productdb.execute("SELECT quantity FROM product_tbl WHERE token = ?", (y[0]))
                initial_qty = productdb.fetchone()[0]
                new_qty = initial_qty + y[1]
                productdb.execute("UPDATE product_tbl SET quantity = ? WHERE name = ?", (new_qty,y[0]))
            productdb.execute("DELETE FROM product_tbl WHERE token = ?", (x))

app = Flask(__name__)

@app.route("/order")
def order():
    orderdata = request.json
    i = 0
    for x in orderdata[""]:
        productdb.execute("SELECT quantity FROM product_tbl WHERE name = ?", (x[0]))
        result = productdb.fetchone()[0]
        if (result > orderdata[1]):
            quantity_left = int(result - x[0])
            productdb.execute("UPDATE product_tbl SET quantity = ? WHERE name = ?", (quantity_left,x[0]))
        else: 
            orderdata["order"].pop(i)
        i += 1
    order_cache_db.execute("INSERT INTO order_cache_tbl VALUES (?, ?)", orderdata[""])
    return jsonify({"token": generate_token()})

@app.route("")
def order_now():
    data = request.json
    token = data["token"]
    if check_token(token):
        order_cache_db.execute("SELECT cached_items FROM order_cache_tbl WHERE token = ?", (token))
        result = order_cache_db.fetchone()[0]
        total =  0
        for x in items:
            price_product = products[x[0]]
            sub = price_product * x[1]
            total += sub
            x.append(sub)
        return render_template_string(total=total, items=items)
    

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
    return "Success"
