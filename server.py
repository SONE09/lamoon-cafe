#!/usr/bin/env python3
"""Lamoon cafe: local HTTP application with persistent, transactional SQLite data."""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import io
import json
import math
import mimetypes
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

APP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_DIR / "lib"))
TZ = timezone(timedelta(hours=7))
CATEGORIES = {"coffee", "tea", "chocolate", "bakery"}
ROLES = {"manager", "cashier", "barista"}
STATUSES = {"new", "preparing", "ready", "served", "cancelled"}
SESSION_SECONDS = 12 * 60 * 60
LABELS = {"Public URL":"ที่อยู่ร้านสำหรับลูกค้า", "Request ID":"รหัสคำสั่งซื้อ", "Product ID":"รหัสเมนู",
          "Order ID":"รหัสออเดอร์", "Table ID":"รหัสโต๊ะ", "Staff ID":"รหัสพนักงาน", "Alert ID":"รหัสการแจ้งเตือน",
          "Stock ID":"รหัสวัตถุดิบ", "Username":"ชื่อผู้ใช้", "Password":"รหัสผ่าน", "Quantity":"จำนวน",
          "Restock quantity":"จำนวนเติมสต๊อก", "Recipe quantity":"ปริมาณวัตถุดิบ", "Price":"ราคา", "Discount":"ส่วนลด",
          "Name":"ชื่อ", "English name":"ชื่อภาษาอังกฤษ", "Description":"คำอธิบาย", "Table name":"ชื่อโต๊ะ", "Seats":"จำนวนที่นั่ง",
          "Stock note":"หมายเหตุสต๊อก", "Item note":"หมายเหตุรายการ", "Order note":"หมายเหตุออเดอร์", "Availability":"การเปิดขาย",
          "Active":"สถานะการใช้งาน", "Rotate":"การเปลี่ยน QR", "name":"ชื่อร้าน", "subtitle":"คำโปรย", "opening_hours":"เวลาเปิดร้าน",
          "open":"สถานะเปิดร้าน", "demo":"โหมดสาธิต"}


def label_text(label):
    return LABELS.get(label,label)


class APIError(Exception):
    def __init__(self, message, status=400):
        self.message, self.status = message, status


def now():
    return datetime.now(TZ).isoformat(timespec="seconds")


def dumps(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def password_hash(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1)
    return "scrypt$" + salt.hex() + "$" + digest.hex()


def verify_password(password, encoded):
    try:
        scheme, salt, expected = encoded.split("$")
        if scheme != "scrypt":
            return False
        actual = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt), n=16384, r=8, p=1)
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False


def string(value, label, limit=200, required=False):
    if not isinstance(value, str):
        raise APIError(label_text(label) + "ต้องเป็นข้อความ")
    value = value.strip()
    if len(value) > limit or (required and not value):
        raise APIError("กรุณากรอก" + label_text(label) + "ให้ครบและไม่เกิน " + str(limit) + " ตัวอักษร")
    return value


def integer(value, label, minimum=0, maximum=1_000_000):
    if type(value) is not int or not minimum <= value <= maximum:
        raise APIError(label_text(label) + "ต้องเป็นจำนวนเต็มระหว่าง " + str(minimum) + " ถึง " + str(maximum))
    return value


def flag(value, label):
    if type(value) is not bool:
        raise APIError("สถานะ" + label_text(label) + "ไม่ถูกต้อง กรุณาเลือกใหม่")
    return value


def quantity(value, label):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 1_000_000:
        raise APIError(label_text(label) + "ต้องมากกว่า 0 และไม่เกิน 1,000,000")
    rounded = round(value, 6)
    if rounded <= 0:
        raise APIError(label_text(label) + "ต้องไม่น้อยกว่า 0.000001")
    return rounded


def public_url(value):
    value = string(value, "Public URL", 500)
    if value:
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise APIError("ที่อยู่ร้านต้องขึ้นต้นด้วย http:// หรือ https:// และไม่มีรหัสผ่านหรือพารามิเตอร์ท้าย URL")
    return value.rstrip("/")


class Cafe:
    def __init__(self, path, configured_url=None):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.login_attempts = {}
        self.login_lock = threading.Lock()
        self.dummy_password = password_hash(secrets.token_urlsafe(24))
        self._initialize(configured_url)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=15000")
        return db

    @contextmanager
    def transaction(self):
        db = self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _initialize(self, configured_url):
        db = self.connect()
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS shop (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS staff (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            name TEXT NOT NULL, role TEXT NOT NULL, password TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS sessions (key TEXT PRIMARY KEY, staff_id INTEGER NOT NULL REFERENCES staff(id),
            csrf TEXT NOT NULL, expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS tables (id INTEGER PRIMARY KEY, name TEXT NOT NULL, seats INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE, active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS stock (id TEXT PRIMARY KEY, name TEXT NOT NULL, qty REAL NOT NULL CHECK(qty>=0),
            unit TEXT NOT NULL, low REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT NOT NULL, en TEXT NOT NULL,
            category TEXT NOT NULL, description TEXT NOT NULL, price INTEGER NOT NULL CHECK(price>=0),
            image TEXT NOT NULL, available INTEGER NOT NULL, recipe TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, number TEXT NOT NULL DEFAULT '',
            table_id INTEGER NOT NULL REFERENCES tables(id), table_name TEXT NOT NULL, status TEXT NOT NULL,
            total INTEGER NOT NULL, subtotal INTEGER NOT NULL, service_charge INTEGER NOT NULL DEFAULT 0,
            vat INTEGER NOT NULL DEFAULT 0, items TEXT NOT NULL, reservation TEXT NOT NULL, note TEXT NOT NULL,
            created_at TEXT NOT NULL, paid INTEGER NOT NULL DEFAULT 0, payment_id INTEGER,
            receipt_key TEXT NOT NULL UNIQUE, request_id TEXT NOT NULL, payload_hash TEXT NOT NULL,
            demo INTEGER NOT NULL DEFAULT 0, UNIQUE(table_id,request_id));
        CREATE TABLE IF NOT EXISTS payments (id INTEGER PRIMARY KEY, table_id INTEGER NOT NULL REFERENCES tables(id),
            table_name TEXT NOT NULL, amount INTEGER NOT NULL, discount INTEGER NOT NULL, method TEXT NOT NULL,
            created_at TEXT NOT NULL, order_ids TEXT NOT NULL, shop_snapshot TEXT NOT NULL,
            staff_id INTEGER NOT NULL REFERENCES staff(id), demo INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, table_id INTEGER NOT NULL REFERENCES tables(id),
            table_name TEXT NOT NULL, type TEXT NOT NULL, created_at TEXT NOT NULL, resolved INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS movements (id INTEGER PRIMARY KEY, stock_id TEXT NOT NULL REFERENCES stock(id),
            quantity REAL NOT NULL, reason TEXT NOT NULL, note TEXT NOT NULL, order_id INTEGER,
            staff_id INTEGER, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, action TEXT NOT NULL, staff_id INTEGER,
            details TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS orders_table_live ON orders(table_id,paid,status);
        CREATE INDEX IF NOT EXISTS orders_created ON orders(created_at);
        CREATE INDEX IF NOT EXISTS payments_created ON payments(created_at);
        """)
        db.close()
        with self.transaction() as db:
            if not db.execute("SELECT 1 FROM shop").fetchone():
                shop = {"name": "ละมุน", "subtitle": "กาแฟหอม ๆ กับขนมชิ้นโปรดของคุณ",
                        "open": True, "demo": True, "opening_hours": "ทุกวัน 08:00–18:00", "service_charge": 0,
                        "vat": 0, "public_url": configured_url or ""}
                db.execute("INSERT INTO shop VALUES(1,?)", (dumps(shop),))
                initial = os.environ.get("LAMOON_ADMIN_PASSWORD") or secrets.token_urlsafe(15)
                if len(initial) < 10:
                    raise APIError("LAMOON_ADMIN_PASSWORD must contain at least 10 characters")
                db.execute("INSERT INTO staff VALUES(1,'admin','ผู้จัดการร้าน','manager',?,1)", (password_hash(initial),))
                stocks = [("coffee", "เมล็ดกาแฟ", 5000, "g", 500), ("milk", "นมสด", 12000, "ml", 1500),
                          ("oat", "นมโอ๊ต", 6000, "ml", 800), ("matcha", "ผงมัทฉะ", 800, "g", 100),
                          ("cocoa", "ผงโกโก้", 1500, "g", 150), ("croissant", "ครัวซองต์", 24, "ชิ้น", 5),
                          ("brownie", "บราวนี", 20, "ชิ้น", 5)]
                db.executemany("INSERT INTO stock VALUES(?,?,?,?,?)", stocks)
                products = [
                    (1,"เอสเพรสโซ","Espresso","coffee","ช็อตกาแฟหอมเข้ม จากเมล็ดคั่วกลาง",65,"",1,{"coffee":18}),
                    (2,"อเมริกาโน","Americano","coffee","กาแฟดำกลมกล่อม สดชื่นในทุกวัน",75,"",1,{"coffee":18}),
                    (3,"ลาเต้","Latte","coffee","เอสเพรสโซและนมนุ่ม ละมุนพอดี",95,"latte",1,{"coffee":18,"milk":180}),
                    (4,"คาปูชิโน","Cappuccino","coffee","กาแฟเข้มกับฟองนมเนียนนุ่ม",95,"",1,{"coffee":18,"milk":160}),
                    (5,"มัทฉะลาเต้","Matcha Latte","tea","มัทฉะหอมละมุน ผสมนมสด",115,"matcha",1,{"matcha":5,"milk":180}),
                    (6,"โกโก้","Cocoa","chocolate","โกโก้เข้มข้นและนมสด หวานตามใจ",95,"",1,{"cocoa":20,"milk":180}),
                    (7,"ครัวซองต์","Butter Croissant","bakery","ครัวซองต์เนยสด กรอบนอกนุ่มใน",85,"croissant",1,{"croissant":1}),
                    (8,"บราวนี","Chocolate Brownie","bakery","บราวนีช็อกโกแลตเนื้อหนึบ",75,"",1,{"brownie":1})]
                db.executemany("INSERT INTO products VALUES(?,?,?,?,?,?,?,?,?)", [p[:-1]+(dumps(p[-1]),) for p in products])
                db.executemany("INSERT INTO tables VALUES(?,?,?,?,1)", [(i, f"{i:02}", 2 if i <= 8 else 4, secrets.token_urlsafe(24)) for i in range(1,13)])
                self._seed_demo(db)
                print("Created cafe database. Initial admin login: admin / " + initial, flush=True)
                print("Demo data is clearly marked DEMO. Change shop demo setting before real service.", flush=True)
            elif configured_url is not None:
                shop = self.shop(db)
                shop["public_url"] = configured_url
                db.execute("UPDATE shop SET value=? WHERE id=1", (dumps(shop),))

    def shop(self, db):
        return json.loads(db.execute("SELECT value FROM shop WHERE id=1").fetchone()[0])

    def audit(self, db, action, user, details):
        db.execute("INSERT INTO audit(action,staff_id,details,created_at) VALUES(?,?,?,?)",
                   (action, user["id"] if user else None, dumps(details), now()))

    def _seed_demo(self, db):
        demo_specs = [(1,"new",[(3,2)]),(3,"preparing",[(5,1),(7,1)]),(7,"ready",[(2,1)]),
                      (2,"served",[(3,1),(8,1)]),(4,"served",[(3,2),(7,1)]),(6,"served",[(5,1),(8,2)])]
        for index, (table_id, status, specs) in enumerate(demo_specs):
            token = db.execute("SELECT token FROM tables WHERE id=?", (table_id,)).fetchone()[0]
            data = {"token":token,"request_id":f"demo-seed-{index}","items":[{"product_id":pid,"qty":qty,"options":{},"note":""} for pid,qty in specs],"note":"คำสั่งซื้อสาธิต • DEMO"}
            order = self.create_order(db, data)
            created = (datetime.now(TZ)-timedelta(minutes=8+index*4)).isoformat(timespec="seconds")
            db.execute("UPDATE orders SET status=?,created_at=? WHERE id=?", (status,created,order["id"]))
            if index >= 4:
                self.make_payment(db, {"table_id":table_id,"method":"cash" if index==4 else "transfer","discount":0}, {"id":1})

    def table_from_token(self, db, token, demo_default=False):
        if token is None and demo_default and self.shop(db)["demo"]:
            row = db.execute("SELECT * FROM tables WHERE id=5 AND active=1").fetchone()
        else:
            if not isinstance(token,str) or len(token) > 120 or not token:
                raise APIError("กรุณาสแกน QR ที่โต๊ะเพื่อสั่งอาหาร", 403)
            row = db.execute("SELECT * FROM tables WHERE token=? AND active=1", (token,)).fetchone()
        if row is None:
            raise APIError("QR โต๊ะนี้หมดอายุ กรุณาขอ QR ใหม่จากพนักงาน", 403)
        return dict(row)

    def products(self, db, customer=False):
        stocks = {r["id"]:r["qty"] for r in db.execute("SELECT * FROM stock")}
        result = []
        for row in db.execute("SELECT * FROM products ORDER BY id"):
            p = dict(row)
            p["recipe"] = json.loads(p["recipe"])
            p["stock_limit"] = max(0,min([int((stocks.get(s,0)+1e-9)//q) for s,q in p["recipe"].items()] or [999]))
            p["available"] = bool(p["available"]) and (p["stock_limit"]>0 if customer else True)
            p["drink"] = p["category"] != "bakery"
            result.append(p)
        return result

    def order_dict(self, row):
        value = dict(row)
        value["items"] = json.loads(value["items"])
        value["paid"] = bool(value["paid"])
        value["demo"] = bool(value["demo"])
        value.pop("reservation",None)
        value.pop("payload_hash",None)
        value.pop("request_id",None)
        return value

    def payment_dict(self, row):
        value = dict(row)
        value["order_ids"] = json.loads(value["order_ids"])
        value["demo"] = bool(value["demo"])
        value.pop("shop_snapshot",None)
        return value

    def normalize_order(self, data):
        request_id = string(data.get("request_id"),"Request ID",120,True)
        if not re.fullmatch(r"[A-Za-z0-9_-]{8,120}", request_id):
            raise APIError("รหัสคำสั่งซื้อไม่ถูกต้อง กรุณารีเฟรชหน้าแล้วลองใหม่")
        items = data.get("items")
        if not isinstance(items,list) or not 1 <= len(items) <= 30:
            raise APIError("กรุณาเลือกอย่างน้อย 1 รายการ (สูงสุด 30 รายการ)")
        result=[]
        for item in items:
            if not isinstance(item,dict):
                raise APIError("รายการที่สั่งไม่ถูกต้อง กรุณาเลือกเมนูใหม่")
            options = item.get("options",{})
            if not isinstance(options,dict):
                raise APIError("ตัวเลือกเครื่องดื่มไม่ถูกต้อง กรุณาเลือกใหม่")
            result.append({"product_id":integer(item.get("product_id"),"Product ID",1),
                           "qty":integer(item.get("qty"),"Quantity",1,20), "options":options,
                           "note":string(item.get("note",""),"Item note",300)})
        return request_id,{"items":result,"note":string(data.get("note",""),"Order note",600)}

    def create_order(self, db, data):
        table = self.table_from_token(db, data.get("token"))
        request_id, normalized = self.normalize_order(data)
        canonical = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        old = db.execute("SELECT * FROM orders WHERE table_id=? AND request_id=?", (table["id"],request_id)).fetchone()
        if old:
            if not hmac.compare_digest(old["payload_hash"],digest):
                raise APIError("รายการในคำสั่งซื้อนี้เปลี่ยนไป กรุณาตรวจสอบออเดอร์เดิมก่อนส่งอีกครั้ง",409)
            return self.order_dict(old)
        shop = self.shop(db)
        if not shop["open"]:
            raise APIError("ขณะนี้ร้านปิดรับออเดอร์",409)
        reservation={}
        lines=[]
        for item in normalized["items"]:
            row = db.execute("SELECT * FROM products WHERE id=?", (item["product_id"],)).fetchone()
            if row is None or not row["available"]:
                raise APIError("เมนูนี้ไม่พร้อมจำหน่าย กรุณาเลือกใหม่",409)
            recipe=json.loads(row["recipe"])
            unit_price=row["price"]
            options={}
            if row["category"] != "bakery":
                supplied=item["options"]
                options={"temperature":supplied.get("temperature","iced"),"size":supplied.get("size","regular"),
                         "sweetness":str(supplied.get("sweetness","50")),"milk":supplied.get("milk","regular"),"shot":supplied.get("shot",False)}
                if options["temperature"] not in ("iced","hot") or options["size"] not in ("regular","large") or options["sweetness"] not in ("0","25","50","100") or options["milk"] not in ("regular","oat") or type(options["shot"]) is not bool:
                    raise APIError("ตัวเลือกเครื่องดื่มไม่ถูกต้อง")
                if options["size"] == "large":
                    unit_price += 15
                    recipe={key:round(q*1.25,6) for key,q in recipe.items()}
                if options["milk"] == "oat":
                    if "milk" not in recipe:
                        raise APIError("เมนูนี้ไม่มีตัวเลือกนมโอ๊ต")
                    unit_price += 20
                    recipe["oat"]=recipe.pop("milk")
                if options["shot"]:
                    if row["category"] != "coffee":
                        raise APIError("เพิ่มช็อตได้เฉพาะเมนูกาแฟ")
                    unit_price += 15
                    recipe["coffee"]=recipe.get("coffee",0)+18
            for stock_id,q in recipe.items():
                reservation[stock_id]=round(reservation.get(stock_id,0)+q*item["qty"],6)
            lines.append({"product_id":row["id"],"name":row["name"],"en":row["en"],"category":row["category"],
                          "qty":item["qty"],"options":options,"note":item["note"],"unit_price":unit_price,
                          "price":unit_price,"total":unit_price*item["qty"]})
        for stock_id,q in reservation.items():
            stock = db.execute("SELECT qty,name FROM stock WHERE id=?",(stock_id,)).fetchone()
            if stock is None or stock["qty"]+1e-9 < q:
                raise APIError("วัตถุดิบไม่เพียงพอ กรุณาปรับรายการหรือสอบถามพนักงาน",409)
        subtotal=sum(item["total"] for item in lines)
        charge=(subtotal*shop["service_charge"]+50)//100
        vat=((subtotal+charge)*shop["vat"]+50)//100
        created=now()
        cur = db.execute("""INSERT INTO orders(table_id,table_name,status,total,subtotal,service_charge,vat,items,reservation,note,
            created_at,receipt_key,request_id,payload_hash,demo) VALUES(?,?,'new',?,?,?,?,?,?,?,?,?,?,?,?)""",
            (table["id"],table["name"],subtotal+charge+vat,subtotal,charge,vat,dumps(lines),dumps(reservation),normalized["note"],created,secrets.token_urlsafe(24),request_id,digest,int(shop["demo"])))
        order_id=cur.lastrowid
        number=f"LM-{datetime.now(TZ):%y%m%d}-{order_id:04}"
        db.execute("UPDATE orders SET number=? WHERE id=?",(number,order_id))
        for stock_id,q in reservation.items():
            db.execute("UPDATE stock SET qty=ROUND(qty-?,6) WHERE id=?",(q,stock_id))
            db.execute("INSERT INTO movements(stock_id,quantity,reason,note,order_id,created_at) VALUES(?,?,'order',?,?,?)",(stock_id,-q,number,order_id,created))
        return self.order_dict(db.execute("SELECT * FROM orders WHERE id=?",(order_id,)).fetchone())

    def update_order(self, db, data, user):
        order_id=integer(data.get("id"),"Order ID",1)
        status=data.get("status")
        row=db.execute("SELECT * FROM orders WHERE id=?",(order_id,)).fetchone()
        if row is None:
            raise APIError("ไม่พบออเดอร์",404)
        allowed={"new":{"preparing","cancelled"},"preparing":{"ready"},"ready":{"served"}}
        if row["paid"] or not isinstance(status,str) or status not in allowed.get(row["status"],set()):
            raise APIError("ไม่สามารถเปลี่ยนสถานะออเดอร์นี้ได้",409)
        if status == "cancelled":
            for stock_id,q in json.loads(row["reservation"]).items():
                db.execute("UPDATE stock SET qty=ROUND(qty+?,6) WHERE id=?",(q,stock_id))
                db.execute("INSERT INTO movements(stock_id,quantity,reason,note,order_id,staff_id,created_at) VALUES(?,?,'cancel',?,?,?,?)",(stock_id,q,row["number"],order_id,user["id"],now()))
        db.execute("UPDATE orders SET status=? WHERE id=?",(status,order_id))
        self.audit(db,"order_status",user,{"id":order_id,"from":row["status"],"to":status})
        return self.order_dict(db.execute("SELECT * FROM orders WHERE id=?",(order_id,)).fetchone())

    def make_payment(self, db, data, user):
        table_id=integer(data.get("table_id"),"Table ID",1)
        method=data.get("method")
        if method not in ("cash","transfer","card"):
            raise APIError("กรุณาเลือกวิธีชำระเงินที่ถูกต้อง")
        discount=integer(data.get("discount",0),"Discount")
        table=db.execute("SELECT * FROM tables WHERE id=?",(table_id,)).fetchone()
        if table is None:
            raise APIError("ไม่พบโต๊ะ",404)
        rows=list(db.execute("SELECT * FROM orders WHERE table_id=? AND paid=0 AND status!='cancelled' ORDER BY id",(table_id,)))
        if not rows:
            raise APIError("โต๊ะนี้ไม่มีรายการค้างชำระ",409)
        if any(r["status"] != "served" for r in rows):
            raise APIError("กรุณาเสิร์ฟออเดอร์ที่ยังไม่เสร็จก่อนรับชำระเงิน",409)
        total=sum(r["total"] for r in rows)
        if discount>total:
            raise APIError("ส่วนลดต้องไม่มากกว่ายอดรวม")
        ids=[r["id"] for r in rows]
        cur=db.execute("INSERT INTO payments(table_id,table_name,amount,discount,method,created_at,order_ids,shop_snapshot,staff_id,demo) VALUES(?,?,?,?,?,?,?,?,?,?)",(table_id,table["name"],total-discount,discount,method,now(),dumps(ids),dumps(self.shop(db)),user["id"],int(all(r["demo"] for r in rows))))
        payment_id=cur.lastrowid
        db.executemany("UPDATE orders SET paid=1,payment_id=? WHERE id=?",[(payment_id,oid) for oid in ids])
        db.execute("UPDATE alerts SET resolved=1 WHERE table_id=? AND type='bill' AND resolved=0",(table_id,))
        self.audit(db,"payment",user,{"id":payment_id,"order_ids":ids,"amount":total-discount})
        return self.payment_dict(db.execute("SELECT * FROM payments WHERE id=?",(payment_id,)).fetchone())

    def report(self, db, query):
        start=query.get("from",[datetime.now(TZ).date().isoformat()])[0]
        end=query.get("to",[start])[0]
        try:
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}",start) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}",end):
                raise ValueError("date format")
            date_start=datetime.strptime(start,"%Y-%m-%d").date()
            date_end=datetime.strptime(end,"%Y-%m-%d").date()
        except (ValueError,TypeError):
            raise APIError("กรุณาเลือกวันที่ที่ถูกต้องในรูปแบบ ปี-เดือน-วัน")
        if date_start>date_end or (date_end-date_start).days>3660:
            raise APIError("วันที่เริ่มต้นต้องไม่เกินวันที่สิ้นสุด และช่วงวันที่ต้องไม่เกิน 10 ปี")
        payments=[self.payment_dict(r) for r in db.execute("SELECT * FROM payments WHERE substr(created_at,1,10)>=? AND substr(created_at,1,10)<=? ORDER BY created_at",(start,end))]
        ids=[oid for p in payments for oid in p["order_ids"]]
        orders=[]
        for oid in ids:
            row=db.execute("SELECT * FROM orders WHERE id=?",(oid,)).fetchone()
            if row:
                orders.append(self.order_dict(row))
        daily={}
        best={}
        for p in payments:
            day=p["created_at"][:10]
            bucket=daily.setdefault(day,{"date":day,"total":0,"count":0})
            bucket["total"]+=p["amount"]
            bucket["count"]+=1
        for order in orders:
            for item in order["items"]:
                bucket=best.setdefault(item["product_id"],{"name":item["name"],"qty":0,"total":0})
                bucket["qty"]+=item["qty"]
                bucket["total"]+=item["total"]
        revenue=sum(p["amount"] for p in payments)
        return {"payments":payments,"orders":orders,"revenue":revenue,"order_count":len(orders),
                "average":round(revenue/len(payments),2) if payments else 0,"best_sellers":sorted(best.values(),key=lambda v:v["qty"],reverse=True),"daily":list(daily.values())}


class Handler(BaseHTTPRequestHandler):
    server_version="Lamoon/1.0"

    @property
    def cafe(self):
        return self.server.cafe

    def log_message(self, fmt, *args):
        # Request URLs can contain table or receipt tokens; do not write them to logs.
        print(f"{self.address_string()} {self.command} {urlparse(self.path).path} {args[1] if len(args)>1 else ''}",flush=True)

    def send(self, value, status=200, cookie=None):
        if getattr(self, "_defer_response", False):
            self._pending_response = (value, status, cookie)
            return
        self.send_bytes(dumps({"ok":True,**value}).encode("utf-8"),"application/json; charset=utf-8",status,cookie)

    def send_bytes(self, body, content_type, status=200, cookie=None, download=None):
        self.send_response(status)
        self.send_header("Content-Type",content_type)
        self.send_header("Content-Length",str(len(body)))
        self.send_header("Cache-Control","no-store")
        self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("X-Frame-Options","SAMEORIGIN")
        self.send_header("Content-Security-Policy","frame-ancestors 'self'")
        self.send_header("Referrer-Policy","no-referrer")
        if cookie:
            self.send_header("Set-Cookie",cookie)
        if download:
            self.send_header("Content-Disposition",f'attachment; filename="{download}"')
        self.end_headers()
        self.wfile.write(body)

    def fail(self, error):
        self.send_bytes(dumps({"ok":False,"error":error.message}).encode("utf-8"),"application/json; charset=utf-8",error.status)

    def body(self):
        if self.headers.get("Content-Type","").split(";",1)[0].strip().lower() != "application/json":
            raise APIError("รูปแบบข้อมูลที่ส่งไม่ถูกต้อง กรุณารีเฟรชหน้าแล้วลองใหม่",415)
        try:
            size=int(self.headers.get("Content-Length","0"))
        except ValueError:
            raise APIError("ข้อมูลที่ส่งไม่ถูกต้อง กรุณาลองใหม่")
        if not 1<=size<=100_000:
            raise APIError("ไม่มีข้อมูลหรือข้อมูลมีขนาดใหญ่เกินไป กรุณาตรวจสอบรายการ",413)
        try:
            result=json.loads(self.rfile.read(size))
        except (json.JSONDecodeError,UnicodeDecodeError):
            raise APIError("ข้อมูลที่ส่งไม่ถูกต้อง กรุณารีเฟรชหน้าแล้วลองใหม่")
        if not isinstance(result,dict):
            raise APIError("รูปแบบข้อมูลไม่ถูกต้อง กรุณาลองใหม่")
        return result

    def origin_check(self):
        origin=self.headers.get("Origin")
        if origin:
            parsed=urlparse(origin)
            expected=self.headers.get("Host","").lower()
            if parsed.scheme not in ("http","https") or parsed.netloc.lower()!=expected:
                raise APIError("กรุณาเปิดร้านจากลิงก์ที่ถูกต้องก่อนทำรายการ",403)

    def session(self, db, required=False, roles=None, mutation=False):
        cookie=SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie",""))
        except Exception:
            pass
        sid=cookie["lamoon_session"].value if "lamoon_session" in cookie else ""
        row=None
        if sid and len(sid)<=100:
            key=hashlib.sha256(sid.encode()).hexdigest()
            row=db.execute("SELECT s.csrf,s.expires,u.id,u.username,u.name,u.role,u.active FROM sessions s JOIN staff u ON u.id=s.staff_id WHERE s.key=? AND s.expires>? AND u.active=1",(key,time.time())).fetchone()
        if row is None:
            if required:
                raise APIError("กรุณาเข้าสู่ระบบพนักงาน",401)
            return None,None
        user={k:row[k] for k in ("id","username","name","role")}
        if roles and user["role"] not in roles:
            raise APIError("บัญชีนี้ไม่มีสิทธิ์ทำรายการ",403)
        if mutation:
            csrf=self.headers.get("X-CSRF-Token","")
            if not hmac.compare_digest(csrf,row["csrf"]):
                raise APIError("กรุณารีเฟรชหน้าแล้วลองทำรายการอีกครั้ง",403)
        return user,row["csrf"]

    def do_GET(self):
        try:
            self.get()
        except APIError as e:
            self.fail(e)
        except (BrokenPipeError,ConnectionResetError):
            pass
        except Exception as e:
            print(f"GET error: {type(e).__name__}: {e}",file=sys.stderr,flush=True)
            self.fail(APIError("เกิดข้อผิดพลาดภายใน กรุณาลองใหม่",500))

    def get(self):
        parsed=urlparse(self.path)
        path=parsed.path
        query=parse_qs(parsed.query)
        if not path.startswith("/api/"):
            return self.static(path)
        db=self.cafe.connect()
        try:
            db.execute("BEGIN")
            if path=="/api/session":
                user,csrf=self.session(db)
                return self.send({"user":user,"csrf":csrf})
            if path=="/api/menu":
                shop=self.cafe.shop(db)
                token=query.get("token",[None])[0]
                table=None
                if token is not None or shop["demo"]:
                    table=self.cafe.table_from_token(db,token,demo_default=True)
                exposed={k:v for k,v in shop.items() if k!="public_url"}
                payload={"shop":exposed,"table":{k:table[k] for k in ("id","name","seats")} if table else None,"products":self.cafe.products(db,customer=True)}
                if shop["demo"]:
                    payload["demo_tables"]=[dict(r) for r in db.execute("SELECT name,token FROM tables WHERE active=1 ORDER BY id")]
                return self.send(payload)
            if path=="/api/order":
                try:
                    oid=int(query.get("id",[""])[0])
                except ValueError:
                    raise APIError("รหัสออเดอร์ไม่ถูกต้อง")
                key=query.get("key",[""])[0]
                if not key or len(key)>120:
                    raise APIError("กรุณาเปิดออเดอร์จากหน้าที่คุณสั่งไว้",403)
                row=db.execute("SELECT * FROM orders WHERE id=? AND receipt_key=?",(oid,key)).fetchone()
                if row is None:
                    raise APIError("ไม่พบออเดอร์",404)
                return self.send({"order":self.cafe.order_dict(row)})
            if path.startswith("/api/admin/"):
                roles={"manager","cashier"} if path in ("/api/admin/receipt","/api/admin/report","/api/admin/report.csv") else None
                self.session(db,required=True,roles=roles)
                if path=="/api/admin/state":
                    return self.send({"shop":self.cafe.shop(db),"products":self.cafe.products(db),
                        "stock":[dict(r) for r in db.execute("SELECT * FROM stock ORDER BY rowid")],
                        "tables":[{**dict(r),"active":bool(r["active"])} for r in db.execute("SELECT * FROM tables ORDER BY id")],
                        "orders":[self.cafe.order_dict(r) for r in db.execute("SELECT * FROM orders WHERE (paid=0 AND status!='cancelled') OR id IN (SELECT id FROM orders ORDER BY id DESC LIMIT 1000) ORDER BY id DESC")],
                        "payments":[self.cafe.payment_dict(r) for r in db.execute("SELECT * FROM payments ORDER BY id DESC LIMIT 1000")],
                        "staff":[{**dict(r),"active":bool(r["active"])} for r in db.execute("SELECT id,username,name,role,active FROM staff ORDER BY id")],
                        "alerts":[{**dict(r),"resolved":bool(r["resolved"])} for r in db.execute("SELECT * FROM alerts WHERE resolved=0 OR id IN (SELECT id FROM alerts ORDER BY id DESC LIMIT 100) ORDER BY id DESC")],
                        "movements":[dict(r) for r in db.execute("SELECT m.*,s.name,s.unit FROM movements m JOIN stock s ON s.id=m.stock_id ORDER BY m.id DESC LIMIT 100")]})
                if path=="/api/admin/receipt":
                    try:
                        pid=int(query.get("id",[""])[0])
                    except ValueError:
                        raise APIError("รหัสใบเสร็จไม่ถูกต้อง")
                    row=db.execute("SELECT * FROM payments WHERE id=?",(pid,)).fetchone()
                    if not row:
                        raise APIError("ไม่พบใบเสร็จ",404)
                    payment=self.cafe.payment_dict(row)
                    orders=[self.cafe.order_dict(db.execute("SELECT * FROM orders WHERE id=?",(oid,)).fetchone()) for oid in payment["order_ids"]]
                    return self.send({"payment":payment,"orders":orders,"shop":json.loads(row["shop_snapshot"])})
                if path in ("/api/admin/report","/api/admin/report.csv"):
                    report=self.cafe.report(db,query)
                    if path.endswith(".csv"):
                        stream=io.StringIO(newline="")
                        writer=csv.writer(stream)
                        writer.writerow(["payment_id","date","table","method","amount_thb","discount_thb","order_ids","demo"])
                        def safe(value):
                            s=str(value)
                            return "'"+s if s.lstrip().startswith(("=","+","-","@")) or s.startswith(("\t","\r","\n")) else s
                        for p in report["payments"]:
                            writer.writerow([safe(p[k]) for k in ("id","created_at","table_name","method","amount","discount","order_ids","demo")])
                        return self.send_bytes(("\ufeff"+stream.getvalue()).encode("utf-8"),"text/csv; charset=utf-8",download="lamoon-payments.csv")
                    return self.send(report)
                if path=="/api/admin/qr":
                    try:
                        tid=int(query.get("table_id",[""])[0])
                    except ValueError:
                        raise APIError("รหัสโต๊ะไม่ถูกต้อง")
                    table=db.execute("SELECT * FROM tables WHERE id=? AND active=1",(tid,)).fetchone()
                    if not table:
                        raise APIError("ไม่พบโต๊ะที่เปิดใช้งาน",404)
                    shop=self.cafe.shop(db)
                    base=shop["public_url"] or self.server.local_url
                    try:
                        import qrcode
                        from qrcode.image.svg import SvgPathImage
                    except ImportError:
                        raise APIError("ระบบสร้าง QR ยังไม่พร้อม กรุณาตรวจสอบไฟล์โปรแกรมหรือแจ้งผู้ดูแล",503)
                    output=io.BytesIO()
                    qrcode.make(base+"/table/"+quote(table["token"],safe=""),image_factory=SvgPathImage,box_size=8,border=4).save(output)
                    return self.send_bytes(output.getvalue(),"image/svg+xml",download=f"lamoon-table-{tid:02}.svg")
            raise APIError("ไม่พบหน้าหรือรายการที่ต้องการ",404)
        finally:
            db.close()

    def do_POST(self):
        try:
            self.origin_check()
            data=self.body()
            self._defer_response=True
            self._pending_response=None
            self.post(urlparse(self.path).path,data)
            # A success is observable only after its transaction has committed.
            self._defer_response=False
            if self._pending_response:
                value,status,cookie=self._pending_response
                self.send(value,status,cookie)
        except APIError as e:
            self._defer_response=False
            self.fail(e)
        except sqlite3.IntegrityError:
            self._defer_response=False
            self.fail(APIError("ข้อมูลซ้ำหรือไม่ถูกต้อง กรุณาตรวจสอบอีกครั้ง",409))
        except (BrokenPipeError,ConnectionResetError):
            pass
        except Exception as e:
            self._defer_response=False
            print(f"POST error: {type(e).__name__}: {e}",file=sys.stderr,flush=True)
            self.fail(APIError("เกิดข้อผิดพลาดภายใน กรุณาลองใหม่",500))

    def do_PUT(self):
        self.fail(APIError("ไม่รองรับการทำรายการนี้",405))

    do_DELETE=do_PUT
    do_PATCH=do_PUT
    do_OPTIONS=do_PUT

    def post(self,path,data):
        if path=="/api/login":
            return self.login(data)
        with self.cafe.transaction() as db:
            if path=="/api/orders":
                return self.send({"order":self.cafe.create_order(db,data)})
            if path=="/api/service":
                table=self.cafe.table_from_token(db,data.get("token"))
                kind=data.get("type")
                if kind not in ("help","bill"):
                    raise APIError("กรุณาเลือกเรียกพนักงานหรือขอเช็กบิล")
                exists=db.execute("SELECT id FROM alerts WHERE table_id=? AND type=? AND resolved=0",(table["id"],kind)).fetchone()
                if exists:
                    alert_id=exists[0]
                else:
                    alert_id=db.execute("INSERT INTO alerts(table_id,table_name,type,created_at) VALUES(?,?,?,?)",(table["id"],table["name"],kind,now())).lastrowid
                return self.send({"id":alert_id})
            user,csrf=self.session(db,required=True,mutation=True)
            if path=="/api/logout":
                db.execute("DELETE FROM sessions WHERE staff_id=? AND csrf=?",(user["id"],csrf))
                return self.send({},cookie="lamoon_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")
            manager_paths={"/api/admin/product","/api/admin/stock","/api/admin/table","/api/admin/staff","/api/admin/settings"}
            if path in manager_paths and user["role"]!="manager":
                raise APIError("เฉพาะผู้จัดการเท่านั้น",403)
            if path=="/api/admin/order":
                return self.send({"order":self.cafe.update_order(db,data,user)})
            if path=="/api/admin/payment":
                if user["role"] not in ("manager","cashier"):
                    raise APIError("เฉพาะผู้จัดการหรือแคชเชียร์เท่านั้น",403)
                payment=self.cafe.make_payment(db,data,user)
                orders=[self.cafe.order_dict(db.execute("SELECT * FROM orders WHERE id=?",(oid,)).fetchone()) for oid in payment["order_ids"]]
                return self.send({"payment":payment,"orders":orders})
            if path=="/api/admin/product":
                return self.product(db,data,user)
            if path=="/api/admin/stock":
                sid=string(data.get("id"),"Stock ID",60,True)
                q=quantity(data.get("quantity"),"Restock quantity")
                note=string(data.get("note",""),"Stock note",300)
                if not db.execute("SELECT id FROM stock WHERE id=?",(sid,)).fetchone():
                    raise APIError("ไม่พบวัตถุดิบ",404)
                db.execute("UPDATE stock SET qty=ROUND(qty+?,6) WHERE id=?",(q,sid))
                db.execute("INSERT INTO movements(stock_id,quantity,reason,note,staff_id,created_at) VALUES(?,?,'restock',?,?,?)",(sid,q,note,user["id"],now()))
                self.cafe.audit(db,"restock",user,{"id":sid,"quantity":q})
                return self.send({"stock":dict(db.execute("SELECT * FROM stock WHERE id=?",(sid,)).fetchone())})
            if path=="/api/admin/table":
                return self.table(db,data,user)
            if path=="/api/admin/staff":
                return self.staff(db,data,user)
            if path=="/api/admin/settings":
                return self.settings(db,data,user)
            if path=="/api/admin/alert":
                aid=integer(data.get("id"),"Alert ID",1)
                if not db.execute("SELECT id FROM alerts WHERE id=?",(aid,)).fetchone():
                    raise APIError("ไม่พบรายการแจ้งเตือน",404)
                db.execute("UPDATE alerts SET resolved=1 WHERE id=?",(aid,))
                return self.send({})
            raise APIError("ไม่พบหน้าหรือรายการที่ต้องการ",404)

    def login(self,data):
        username=string(data.get("username"),"Username",60,True)
        password=data.get("password")
        if not isinstance(password,str) or not 1 <= len(password) <= 256:
            raise APIError("กรุณากรอกรหัสผ่านที่ถูกต้อง")
        throttle=(self.client_address[0],username.casefold())
        with self.cafe.login_lock:
            attempts=[t for t in self.cafe.login_attempts.get(throttle,[]) if t>time.time()-600]
            if len(attempts)>=8:
                raise APIError("พยายามเข้าสู่ระบบหลายครั้ง กรุณารอ 10 นาที",429)
            self.cafe.login_attempts[throttle]=attempts+[time.time()]
        with self.cafe.transaction() as db:
            row=db.execute("SELECT * FROM staff WHERE username=? AND active=1",(username,)).fetchone()
            valid=verify_password(password,row["password"] if row else self.cafe.dummy_password)
            if row is None or not valid:
                raise APIError("ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง",401)
            sid=secrets.token_urlsafe(32)
            csrf=secrets.token_urlsafe(32)
            db.execute("DELETE FROM sessions WHERE expires<=?",(time.time(),))
            db.execute("INSERT INTO sessions VALUES(?,?,?,?)",(hashlib.sha256(sid.encode()).hexdigest(),row["id"],csrf,time.time()+SESSION_SECONDS))
            user={k:row[k] for k in ("id","username","name","role")}
            self.cafe.audit(db,"login",user,{})
        with self.cafe.login_lock:
            self.cafe.login_attempts.pop(throttle,None)
        secure="; Secure" if self.headers.get("Origin","").startswith("https://") else ""
        return self.send({"user":user,"csrf":csrf},cookie=f"lamoon_session={sid}; Path=/; Max-Age={SESSION_SECONDS}; HttpOnly; SameSite=Strict{secure}")

    def product(self,db,data,user):
        pid=data.get("id")
        if pid is not None:
            integer(pid,"Product ID",1)
            if not db.execute("SELECT id FROM products WHERE id=?",(pid,)).fetchone():
                raise APIError("ไม่พบเมนู",404)
        category=data.get("category")
        if not isinstance(category,str) or category not in CATEGORIES:
            raise APIError("กรุณาเลือกหมวดหมู่เมนูที่ถูกต้อง")
        image=data.get("image","")
        if image not in ("","latte","matcha","croissant"):
            raise APIError("กรุณาเลือกรูปเมนูที่ถูกต้อง")
        recipe=data.get("recipe")
        if not isinstance(recipe,dict) or not recipe:
            raise APIError("กรุณาระบุสูตรวัตถุดิบอย่างน้อยหนึ่งรายการ")
        valid={r[0] for r in db.execute("SELECT id FROM stock")}
        if any(key not in valid for key in recipe):
            raise APIError("ไม่พบวัตถุดิบในสูตร กรุณาตรวจสอบรายการอีกครั้ง")
        recipe={key:quantity(value,"Recipe quantity") for key,value in recipe.items()}
        values=(string(data.get("name"),"Name",120,True),string(data.get("en",""),"English name",120),category,
                string(data.get("description",""),"Description",500),integer(data.get("price"),"Price",1,100000),image,int(flag(data.get("available",True),"Availability")),dumps(recipe))
        if pid:
            db.execute("UPDATE products SET name=?,en=?,category=?,description=?,price=?,image=?,available=?,recipe=? WHERE id=?",values+(pid,))
        else:
            pid=db.execute("INSERT INTO products(name,en,category,description,price,image,available,recipe) VALUES(?,?,?,?,?,?,?,?)",values).lastrowid
        self.cafe.audit(db,"product",user,{"id":pid})
        return self.send({"product":next(p for p in self.cafe.products(db) if p["id"]==pid)})

    def table(self,db,data,user):
        tid=integer(data.get("id"),"Table ID",1)
        row=db.execute("SELECT * FROM tables WHERE id=?",(tid,)).fetchone()
        if not row:
            raise APIError("ไม่พบโต๊ะ",404)
        active=flag(data.get("active",bool(row["active"])),"Active")
        rotate=flag(data.get("rotate",False),"Rotate")
        name=string(data.get("name",row["name"]),"Table name",80,True)
        seats=integer(data.get("seats",row["seats"]),"Seats",1,20)
        occupied=db.execute("SELECT id FROM orders WHERE table_id=? AND paid=0 AND status!='cancelled' LIMIT 1",(tid,)).fetchone()
        if occupied and (rotate or not active or name!=row["name"]):
            raise APIError("กรุณาปิดบิลโต๊ะนี้ก่อนเปลี่ยนชื่อ ปิดโต๊ะ หรือเปลี่ยน QR",409)
        token=secrets.token_urlsafe(24) if rotate else row["token"]
        db.execute("UPDATE tables SET name=?,seats=?,active=?,token=? WHERE id=?",(name,seats,int(active),token,tid))
        self.cafe.audit(db,"table",user,{"id":tid,"rotate":rotate,"active":active})
        value=dict(db.execute("SELECT * FROM tables WHERE id=?",(tid,)).fetchone())
        value["active"]=bool(value["active"])
        return self.send({"table":value})

    def staff(self,db,data,user):
        uid=data.get("id")
        row=None
        if uid is not None:
            integer(uid,"Staff ID",1)
            row=db.execute("SELECT * FROM staff WHERE id=?",(uid,)).fetchone()
            if not row:
                raise APIError("ไม่พบพนักงาน",404)
        username=string(data.get("username",row["username"] if row else ""),"Username",60,True)
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,60}",username):
            raise APIError("ชื่อผู้ใช้ต้องมี 3–60 ตัวอักษร ใช้ภาษาอังกฤษ ตัวเลข จุด ขีดกลาง หรือขีดล่าง")
        name=string(data.get("name",row["name"] if row else ""),"Name",120,True)
        role=data.get("role",row["role"] if row else None)
        if not isinstance(role,str) or role not in ROLES:
            raise APIError("กรุณาเลือกสิทธิ์พนักงานที่ถูกต้อง")
        active=flag(data.get("active",bool(row["active"]) if row else True),"Active")
        if uid==user["id"] and (not active or role!="manager"):
            raise APIError("ไม่สามารถปิดบัญชีหรือลดสิทธิ์ของตนเองได้",409)
        if row and row["active"] and row["role"]=="manager" and (not active or role!="manager"):
            if db.execute("SELECT COUNT(*) FROM staff WHERE active=1 AND role='manager'").fetchone()[0]<=1:
                raise APIError("ต้องมีผู้จัดการที่ใช้งานได้อย่างน้อยหนึ่งคน",409)
        password=data.get("password","")
        if not isinstance(password,str) or len(password)>256:
            raise APIError("รหัสผ่านไม่ถูกต้องหรือยาวเกิน 256 ตัวอักษร")
        if password and len(password)<10 or not row and not password:
            raise APIError("รหัสผ่านต้องมีอย่างน้อย 10 ตัวอักษร")
        encoded=password_hash(password) if password else row["password"]
        if row:
            db.execute("UPDATE staff SET username=?,name=?,role=?,password=?,active=? WHERE id=?",(username,name,role,encoded,int(active),uid))
            if password or not active or role!=row["role"]:
                db.execute("DELETE FROM sessions WHERE staff_id=?",(uid,))
        else:
            uid=db.execute("INSERT INTO staff(username,name,role,password,active) VALUES(?,?,?,?,?)",(username,name,role,encoded,int(active))).lastrowid
        self.cafe.audit(db,"staff",user,{"id":uid,"role":role,"active":active})
        return self.send({"staff":{"id":uid,"username":username,"name":name,"role":role,"active":active}})

    def settings(self,db,data,user):
        shop=self.cafe.shop(db)
        for key,limit in (("name",120),("subtitle",200),("opening_hours",200)):
            if key in data:
                shop[key]=string(data[key],key,limit,key=="name")
        for key in ("open","demo"):
            if key in data:
                shop[key]=flag(data[key],key)
        if "public_url" in data:
            shop["public_url"]=public_url(data["public_url"])
        db.execute("UPDATE shop SET value=? WHERE id=1",(dumps(shop),))
        self.cafe.audit(db,"settings",user,{"open":shop["open"],"demo":shop["demo"]})
        return self.send({"shop":shop})

    def static(self,path):
        if path in ("/","/admin","/admin/") or re.fullmatch(r"/table/[A-Za-z0-9_-]{16,120}/?",path):
            target=APP_DIR/"static"/"index.html"
        elif path.startswith("/static/"):
            root=(APP_DIR/"static").resolve()
            target=(APP_DIR/path.lstrip("/")).resolve()
            if not target.is_relative_to(root):
                raise APIError("ไม่พบหน้าหรือรายการที่ต้องการ",404)
        elif path=="/favicon.ico":
            self.send_bytes(b"","image/x-icon",204)
            return
        else:
            raise APIError("ไม่พบหน้าหรือรายการที่ต้องการ",404)
        if not target.is_file():
            raise APIError("ไม่พบหน้าหรือรายการที่ต้องการ",404)
        mime=mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if mime.startswith("text/") or mime in ("application/javascript","application/json"):
            mime+="; charset=utf-8"
        return self.send_bytes(target.read_bytes(),mime)


def build_server(host="127.0.0.1",port=8787,db=None,configured_url=None):
    cafe=Cafe(Path(db) if db else APP_DIR/"data"/"cafe.db",configured_url)
    server=ThreadingHTTPServer((host,port),Handler)
    server.daemon_threads=True
    server.cafe=cafe
    address=server.server_address[0]
    if address in ("0.0.0.0","::"):
        address="127.0.0.1"
    server.local_url=f"http://{address}:{server.server_address[1]}"
    return server


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host",default="127.0.0.1",help="Use 0.0.0.0 for other devices on a trusted LAN")
    parser.add_argument("--port",type=int,default=8787)
    parser.add_argument("--db",default=str(APP_DIR/"data"/"cafe.db"))
    parser.add_argument("--public-url",default=None,help="Customer reachable base URL used in table QR codes")
    args=parser.parse_args()
    try:
        configured=public_url(args.public_url) if args.public_url is not None else None
        server=build_server(args.host,args.port,args.db,configured)
    except (APIError,OSError) as e:
        parser.error(e.message if isinstance(e,APIError) else str(e))
    print(f"Lamoon cafe running at {server.local_url}; database: {server.cafe.path}",flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__=="__main__":
    main()
