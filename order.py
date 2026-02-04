from flask import Flask, jsonify, request, render_template_string, abort
from flask_limiter import Limiter
from flask_cors import CORS
from sqlalchemy import create_engine, text
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import secrets
import json
import bleach
import requests
import hashlib
import hmac
import schedule
import time
import datetime
import threading
import os

# ---------------- CONFIG (ENV REQUIRED) ----------------

BILLPLZ_API_KEY = os.environ["BILLPLZ_API_KEY"]
SECRET_KEY = os.environ["SECRET_KEY"]

# ---------------- APP ----------------

app = Flask(__name__)

CORS(
    app,
    origins=["https://yourdomain.com"],
    supports_credentials=True
)

limiter = Limiter(app=app, key_func=lambda: request.remote_addr, storage_uri="rediss://default:AUnRAAIncDI3YTk1YTk5NjBmYzU0YWY0OWMzZTRiMDBjNGJiZmYwYXAyMTg4OTc@enormous-mule-18897.upstash.io:6379",
storage_options={"socket_connect_timeout": 9}, fail_on_first_breach = True)

# ---------------- DB ----------------

productdb = create_engine("mysql+pymysql://4J4VubRMtDYVKrk.root:UtLbWgr32k7ka8sW@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/perfume_product_db", pool_pre_ping=True)
order_cache_db = create_engine("mysql+pymysql://488EN1h3SHK5USZ.root:tZHWCFdtOqa8pvrt@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/", pool_pre_ping=True)
orderdb = create_engine("mysql+pymysql://3ePjuz2Qec5Dphc.root:TFHd3bdTUar44EQL@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/order_db", pool_pre_ping=True)
reservedb = create_engine("mysql+pymysql://2ufYbQ2RxhJDTsn.root:pjStpb6AMMurZuqS@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/stock_reservation_db", pool_pre_ping=True)
# ---------------- TOKEN ----------------

serializer = URLSafeTimedSerializer(SECRET_KEY)
TOKEN_SALT = "bcsfo"

def generate_token():
    return serializer.dumps(secrets.token_hex(16), salt=TOKEN_SALT)

def check_token(token):
    try:
        serializer.loads(token, salt=TOKEN_SALT, max_age=900)
        return True
    except (BadSignature, SignatureExpired):
        return False

# ---------------- CACHE ----------------

product_data = {}
product_lock = threading.Lock()

def product_fetch():
    with productdb.connect() as conn:
        rows = conn.execute(text("SELECT name, img_link FROM product_tbl"))
        with product_lock:
            product_data.clear()
            for n, i in rows:
                product_data[n] = i

# ---------------- CLEANUP ----------------

def cleanup_reservations():
    with productdb.begin() as conn:
        conn.execute(text("""
            DELETE FROM stock_reservation
            WHERE expires_at < NOW()
        """))

def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(5)

schedule.every(1).minutes.do(cleanup_reservations)
threading.Thread(target=run_scheduler, daemon=True).start()

# ---------------- ORDER FIRST ----------------

@app.route("/order_first", methods=["POST"])
@limiter.limit("10/minute")
def order_first():
    data = request.get_json()
    if not data or "order_items" not in data:
        abort(400)

    token = generate_token()
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    total = 0
    items = []

    with productdb.begin() as conn:
        for name, qty in data["order_items"]:
            name = bleach.clean(name)
            qty = int(qty)
            if qty <= 0:
                abort(400)

            row = conn.execute(
                text("SELECT quantity, price FROM product_tbl WHERE name=:n FOR UPDATE"),
                {"n": name}
            ).fetchone()

            if not row:
                abort(404)

            stock, price = row

            reserved = conn.execute(
                text("""
                    SELECT COALESCE(SUM(qty),0)
                    FROM stock_reservation
                    WHERE product_name=:n AND expires_at > NOW()
                """),
                {"n": name}
            ).scalar()

            if stock - reserved < qty:
                abort(400)

            conn.execute(
                text("""
                    INSERT INTO stock_reservation
                    (token, product_name, qty, expires_at)
                    VALUES (:t, :n, :q, :e)
                """),
                {"t": token, "n": name, "q": qty, "e": expires_at}
            )

            img = product_data.get(name, "")
            sub = price * qty
            total += sub
            items.append([name, qty, sub, img])

    with order_cache_db.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO order_cache_tbl (token, cached_items)
                VALUES (:t, :c)
            """),
            {"t": token, "c": json.dumps({"order_json": items, "total": total})}
        )

    return jsonify({"token": token})

# ---------------- RENDER ORDER ----------------

@app.route("/render_order", methods=["POST"])
def render_order():
    token = request.json.get("token")
    if not check_token(token):
        abort(403)

    with order_cache_db.connect() as conn:
        row = conn.execute(
            text("SELECT cached_items FROM order_cache_tbl WHERE token=:t"),
            {"t": token}
        ).fetchone()

    if not row:
        abort(403)

    data = json.loads(row[0])
    return render_template_string("""
    <h1>Order</h1>
    <p>Total: RM{{ total }}</p>
    {% for x in items %}
      <p>{{ x[0] }} ({{ x[1] }}) RM{{ x[2] }}</p>
    {% endfor %}
    """, items=data["order_json"], total=data["total"])

# ---------------- FINAL ORDER ----------------

@app.route("/order", methods=["POST"])
@limiter.limit("5/minute")
def final_order():
    data = request.get_json()
    token = data.get("token")

    if not check_token(token):
        abort(403)

    with order_cache_db.begin() as conn:
        row = conn.execute(
            text("""
                SELECT cached_items
                FROM order_cache_tbl
                WHERE token=:t
                FOR UPDATE
            """),
            {"t": token}
        ).fetchone()

        if not row:
            abort(403)

        cached = json.loads(row[0])
        conn.execute(text("DELETE FROM order_cache_tbl WHERE token=:t"), {"t": token})

    order_id = secrets.token_urlsafe(20)

    address = {}
    for k in ("line1", "city", "state", "postcode"):
        if k not in data["address"]:
            abort(400)
        address[k] = bleach.clean(data["address"][k])

    with orderdb.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO order_tbl
                (order_id, email, phone_no, order_items, address, token,
                 payment_status)
                VALUES (:i,:e,:p,:o,:a,:t,'PENDING')
            """),
            {
                "i": order_id,
                "e": data["email"],
                "p": data["phone_no"],
                "o": json.dumps({x[0]: x[1] for x in cached["order_json"]}),
                "a": json.dumps(address),
                "t": token
            }
        )

    payload = {
        "collection_id": os.environ["BILLPLZ_COLLECTION_ID"],
        "email": data["email"],
        "name": "Customer",
        "amount": int(cached["total"] * 100),
        "callback_url": "https://yourdomain.com/callback",
        "description": "Order payment"
    }

    r = requests.post(
        "https://www.billplz.com/api/v3/bills",
        auth=(BILLPLZ_API_KEY, ""),
        data=payload,
        timeout=10
    )
    r.raise_for_status()

    bill = r.json()
    with orderdb.begin() as conn:
        conn.execute(
            text("""
                UPDATE order_tbl
                SET billplz_id=:b
                WHERE order_id=:o
            """),
            {"b": bill["id"], "o": order_id}
        )

    return jsonify({"order_id": order_id, "link": bill["url"]})

# ---------------- CALLBACK ----------------

@app.route("/callback", methods=["POST"])
@limiter.limit("30/minute")
def callback():
    d = request.form.to_dict()

    signing = (
        f"billplz[id]{d.get('billplz[id]')}|"
        f"billplz[paid]{d.get('billplz[paid]')}|"
        f"billplz[paid_at]{d.get('billplz[paid_at]')}|"
        f"billplz[paid_amount]{d.get('billplz[paid_amount]')}"
    )

    sig = hmac.new(
        BILLPLZ_API_KEY.encode(),
        signing.encode(),
        hashlib.sha256
    ).hexdigest()

    if sig != d.get("billplz[x_signature]"):
        abort(403)

    with orderdb.begin() as conn:
        row = conn.execute(
            text("""
                SELECT order_id, payment_status, order_items, token
                FROM order_tbl
                WHERE billplz_id=:b
                FOR UPDATE
            """),
            {"b": d["billplz[id]"]}
        ).fetchone()

        if not row:
            abort(404)

        oid, status, items_json, token = row
        if status == "PAID":
            return "OK", 200

        items = json.loads(items_json)

        if d.get("billplz[paid]") in ("true", "1"):
            with productdb.begin() as p:
                for name, qty in items.items():
                    p.execute(
                        text("""
                            UPDATE product_tbl
                            SET quantity = quantity - :q
                            WHERE name=:n
                        """),
                        {"q": qty, "n": name}
                    )
                p.execute(
                    text("DELETE FROM stock_reservation WHERE token=:t"),
                    {"t": token}
                )

            conn.execute(
                text("""
                    UPDATE order_tbl
                    SET payment_status='PAID',
                        paid_at=:pa,
                        paid_amount=:amt
                    WHERE order_id=:o
                """),
                {
                    "pa": d.get("billplz[paid_at]"),
                    "amt": d.get("billplz[paid_amount]"),
                    "o": oid
                }
            )
        else:
            conn.execute(
                text("""
                    UPDATE order_tbl
                    SET payment_status='FAILED'
                    WHERE order_id=:o
                """),
                {"o": oid}
            )

    return "OK", 200

# ---------------- INIT ----------------

@app.route("/")
def reload():
    product_fetch()
    return "OK"
