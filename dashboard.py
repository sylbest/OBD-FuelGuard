from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_cors import CORS
from supabase import create_client, Client
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
import os
import re
import secrets

# ===== LOAD ENV =====
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_KEY in .env")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ===== APP SETUP =====
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# ---- Session cookie persistence ----
app.config['SESSION_COOKIE_NAME'] = 'obd_session'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False   # ⚠️ True only for HTTPS in production
app.config['SESSION_COOKIE_PATH'] = '/'
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

CORS(app,
     origins=[
         "http://127.0.0.1:5000",
         "http://localhost:5000",
         "http://127.0.0.1:5500",
         "http://localhost:5500",
     ],
     supports_credentials=True,
     allow_headers=["Content-Type"],
     methods=["GET", "POST", "OPTIONS"])


# ============================================================
# HELPERS
# ============================================================

def is_valid_email(email: str) -> bool:
    """Basic email format check."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def is_valid_phone(phone: str) -> bool:
    """Malaysian phone: +60 or 0, then 9-10 digits."""
    pattern = r'^(\+?60|0)[0-9]{8,10}$'
    cleaned = phone.replace("-", "").replace(" ", "")
    return bool(re.match(pattern, cleaned))


def is_strong_password(password: str) -> tuple:
    """Password must be 8+ chars with letters and numbers."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter."
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number."
    return True, "OK"


def get_user_by_email(email: str):
    """Fetch a user record by email from Supabase."""
    try:
        res = supabase.table("User").select("*").eq("Email", email.lower()).execute()
        return res.data[0] if res.data else None
    except Exception as e:
        print(f"[ERROR] get_user_by_email: {e}")
        return None


def log_activity(user_id, event: str, metadata: dict = None):
    """Write an activity log entry (optional)."""
    try:
        supabase.table("activity_log").insert({
            "user_id": user_id,
            "event": event,
            "metadata": metadata or {},
            "created_at": datetime.now(timezone.utc).isoformat()
        }).execute()
    except Exception as e:
        print(f"[WARN] Could not log activity: {e}")


# ============================================================
# PAGE ROUTES
# ============================================================

@app.route("/")
def home():
    return render_template('index.html')

@app.route("/aboutus")
def about():
    return render_template('About.html') 

@app.route("/sol")
def sol():
    return render_template('solution.html') 

@app.route("/auth")
def auth_page():
    return render_template('auth.html')


@app.route("/dashboard")
def dashboard():
    """Protected dashboard — requires login."""
    if not session.get("user_id"):
        return redirect(url_for("auth_page"))
    return render_template('profile.html', user=session.get("user"))


@app.route("/profile")
def profile_page():
    """Protected profile page — requires login."""
    if not session.get("user_id"):
        return redirect(url_for("auth_page"))
    return render_template("profile.html", user=session.get("user"))


# ============================================================
# AUTH API — SIGNUP (auto-login, no OTP)
# ============================================================

@app.route("/api/signup", methods=["POST"])
def api_signup():
    data = request.get_json(silent=True) or {}

    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    phone = (data.get("phone") or "").strip()
    country = (data.get("country") or "").strip()
    state = (data.get("state") or "").strip()
    password = data.get("password") or ""
    confirm = data.get("confirm") or ""
    age = data.get("age")

    # ---- Age validation ----
    try:
        age_int = int(age)
        if age_int < 18 or age_int > 120:
            return jsonify({"success": False, "error": "Age must be between 18 and 120."}), 400
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid age."}), 400

    # ---- Required fields ----
    if not all([name, email, phone, country, state, password, confirm]):
        return jsonify({"success": False, "error": "All fields are required."}), 400

    # ---- Format validation ----
    if not is_valid_email(email):
        return jsonify({"success": False, "error": "Invalid email format."}), 400

    if not is_valid_phone(phone):
        return jsonify({"success": False, "error": "Invalid phone number format."}), 400

    if password != confirm:
        return jsonify({"success": False, "error": "Passwords do not match."}), 400

    ok, msg = is_strong_password(password)
    if not ok:
        return jsonify({"success": False, "error": msg}), 400

    # ---- Check existing ----
    if get_user_by_email(email):
        return jsonify({"success": False, "error": "An account with this email already exists."}), 409

    # ---- Create user ----
    try:
        password_hash = generate_password_hash(password)
        payload = {
            "Name": name,
            "Email": email,
            "Phone": phone,
            "Country": country,
            "State": state,
            "Password": password_hash,
            "Age": age_int,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        res = supabase.table("User").insert(payload).execute()

        if not res.data:
            return jsonify({"success": False, "error": "Failed to create account."}), 500

        user = res.data[0]
        user_id = user["id"]

        # ---- AUTO-LOGIN after signup ----
        session.permanent = True
        session["user_id"] = user_id
        session["user"] = {
            "id": user_id,
            "name": name,
            "email": email,
            "phone": phone,
            "country": country,
            "state": state,
            "age": age_int
        }

        log_activity(user_id, "signup", {"email": email, "country": country, "state": state})

        return jsonify({
            "success": True,
            "message": "Account created successfully. You are now logged in.",
            "user_id": user_id,
            "user": session["user"]
        }), 201

    except Exception as e:
        print(f"[ERROR] signup: {e}")
        return jsonify({"success": False, "error": "Server error. Please try again."}), 500


# ============================================================
# AUTH API — LOGIN
# ============================================================

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    remember = bool(data.get("remember", False))

    if not email or not password:
        return jsonify({"success": False, "error": "Email and password required."}), 400

    user = get_user_by_email(email)
    if not user:
        return jsonify({"success": False, "error": "Invalid email or password."}), 401

    stored_hash = user.get("Password") or user.get("password_hash") or ""

    if not check_password_hash(stored_hash, password):
        log_activity(user.get("id"), "login_failed", {"email": email})
        return jsonify({"success": False, "error": "Invalid email or password."}), 401

    # ---- Create session (always permanent) ----
    session.permanent = True

    # Adjust lifetime based on "remember me"
    if remember:
        app.permanent_session_lifetime = timedelta(days=30)
    else:
        app.permanent_session_lifetime = timedelta(days=1)

    session["user_id"] = user["id"]
    session["user"] = {
        "id": user["id"],
        "name": user.get("Name"),
        "email": user.get("Email"),
        "phone": user.get("Phone"),
        "country": user.get("Country"),
        "state": user.get("State"),
        "age": user.get("Age")
    }

    log_activity(user["id"], "login_success", {"email": email})

    return jsonify({
        "success": True,
        "message": "Login successful.",
        "user": session["user"]
    }), 200


# ============================================================
# AUTH API — LOGOUT
# ============================================================

@app.route("/logout", methods=["POST", "GET"])
def logout():
    user_id = session.get("user_id")
    if user_id:
        log_activity(user_id, "logout")
    session.clear()
    return redirect(url_for("home"))  # or redirect("/")

@app.route("/logout", methods=["POST", "GET"])
def log():
    user_id = session.get("user_id")
    if user_id:
        log_activity(user_id, "logout")
    session.clear()
    return redirect(url_for("home"))  # or redirect("/")
# ============================================================
# AUTH API — FORGOT PASSWORD (support stub)
# ============================================================

@app.route("/api/forgot-password", methods=["POST"])
def api_forgot_password():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    if not email:
        return jsonify({"success": False, "error": "Email required."}), 400

    # Always return success to prevent email enumeration
    return jsonify({
        "success": True,
        "message": "If an account exists with that email, please contact support to reset your password."
    }), 200


# ============================================================
# CURRENT USER
# ============================================================

@app.route("/api/me", methods=["GET"])
def api_me():
    if not session.get("user_id"):
        return jsonify({"success": False, "error": "Not logged in."}), 401
    return jsonify({"success": True, "user": session.get("user")}), 200


# ============================================================
# DEBUG — session inspector (remove in production)
# ============================================================

@app.route("/api/debug/session", methods=["GET"])
def debug_session():
    """Temporary route to verify session persistence."""
    return jsonify({
        "session_keys": list(session.keys()),
        "user_id": session.get("user_id"),
        "user": session.get("user"),
        "cookie_name": app.config.get('SESSION_COOKIE_NAME'),
        "permanent": session.permanent if "user_id" in session else None,
    }), 200


# ============================================================
# PROFILE API — GET
# ============================================================

@app.route("/api/profile", methods=["GET"])
def api_profile_get():
    """Return the logged-in user's profile."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "Not logged in."}), 401

    try:
        res = supabase.table("User").select(
            "id, Name, Email, Phone, Country, State, Age, created_at"
        ).eq("id", user_id).execute()

        if not res.data:
            return jsonify({"success": False, "error": "User not found."}), 404

        return jsonify({"success": True, "user": res.data[0]}), 200

    except Exception as e:
        print(f"[ERROR] api_profile_get: {e}")
        return jsonify({"success": False, "error": "Server error."}), 500


# ============================================================
# PROFILE API — UPDATE
# ============================================================

@app.route("/api/profile/update", methods=["POST"])
def api_profile_update():
    """Update editable profile fields. Email is NOT editable."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "Not logged in."}), 401

    data = request.get_json(silent=True) or {}

    name = (data.get("name") or "").strip()
    phone = (data.get("phone") or "").strip()
    country = (data.get("country") or "").strip()
    state = (data.get("state") or "").strip()
    age = data.get("age")

    if not all([name, phone, country, state, age]):
        return jsonify({"success": False, "error": "All fields are required."}), 400

    try:
        age_int = int(age)
        if age_int < 18 or age_int > 120:
            return jsonify({"success": False, "error": "Age must be between 18 and 120."}), 400
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid age."}), 400

    if not is_valid_phone(phone):
        return jsonify({"success": False, "error": "Invalid phone number format."}), 400

    try:
        supabase.table("User").update({
            "Name": name,
            "Phone": phone,
            "Country": country,
            "State": state,
            "Age": age_int,
        }).eq("id", user_id).execute()

        session["user"] = {
            **session.get("user", {}),
            "name": name,
            "phone": phone,
            "country": country,
            "state": state,
            "age": age_int,
        }

        log_activity(user_id, "profile_updated")

        return jsonify({"success": True, "message": "Profile updated successfully."}), 200

    except Exception as e:
        print(f"[ERROR] api_profile_update: {e}")
        return jsonify({"success": False, "error": "Server error."}), 500


# ============================================================
# PROFILE API — CHANGE PASSWORD
# ============================================================

@app.route("/api/profile/change-password", methods=["POST"])
def api_profile_change_password():
    """Change password. Requires current password verification."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "Not logged in."}), 401

    data = request.get_json(silent=True) or {}
    current = data.get("current_password") or ""
    new_pass = data.get("new_password") or ""
    confirm = data.get("confirm_password") or ""

    if not current or not new_pass or not confirm:
        return jsonify({"success": False, "error": "All fields are required."}), 400

    if new_pass != confirm:
        return jsonify({"success": False, "error": "New passwords do not match."}), 400

    ok, msg = is_strong_password(new_pass)
    if not ok:
        return jsonify({"success": False, "error": msg}), 400

    if current == new_pass:
        return jsonify({"success": False, "error": "New password must differ from current."}), 400

    try:
        res = supabase.table("User").select("Password").eq("id", user_id).execute()
        if not res.data:
            return jsonify({"success": False, "error": "User not found."}), 404

        stored_hash = res.data[0].get("Password") or ""

        if not check_password_hash(stored_hash, current):
            log_activity(user_id, "password_change_failed")
            return jsonify({"success": False, "error": "Current password is incorrect."}), 401

        new_hash = generate_password_hash(new_pass)
        supabase.table("User").update({"Password": new_hash}).eq("id", user_id).execute()

        log_activity(user_id, "password_changed")

        return jsonify({"success": True, "message": "Password changed successfully."}), 200

    except Exception as e:
        print(f"[ERROR] api_profile_change_password: {e}")
        return jsonify({"success": False, "error": "Server error."}), 500

# ============================================================
# OBD DASHBOARD API
# ============================================================

@app.route("/obd-dashboard")
def obd_dashboard_page():
    """Protected OBD dashboard page."""
    if not session.get("user_id"):
        return redirect(url_for("auth_page"))
    return render_template("obd_dashboard.html")


@app.route("/api/obd/latest", methods=["GET"])
def api_obd_latest():
    """Get the latest reading per plate number (or all plates)."""
    if not session.get("user_id"):
        return jsonify({"success": False, "error": "Not logged in."}), 401

    plate = request.args.get("plate", "").strip()

    try:
        # Fetch latest 500 rows (then dedupe client-side by plate)
        query = supabase.table("OBD_Data").select("*").order("Timestamp", desc=True).limit(500)
        if plate:
            query = query.eq("Plate_Number", plate)

        res = query.execute()
        rows = res.data or []

        # Deduplicate — keep latest per plate
        latest_by_plate = {}
        for r in rows:
            p = r.get("Plate_Number")
            if p and p not in latest_by_plate:
                latest_by_plate[p] = r

        return jsonify({
            "success": True,
            "count": len(latest_by_plate),
            "plates": list(latest_by_plate.keys()),
            "data": list(latest_by_plate.values())
        }), 200

    except Exception as e:
        print(f"[ERROR] api_obd_latest: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/obd/history/<plate>", methods=["GET"])
def api_obd_history(plate):
    """Get recent history for one plate (for charts)."""
    if not session.get("user_id"):
        return jsonify({"success": False, "error": "Not logged in."}), 401

    limit = min(int(request.args.get("limit", 100)), 500)

    try:
        res = (supabase.table("OBD_Data")
               .select("*")
               .eq("Plate_Number", plate)
               .order("Timestamp", desc=True)
               .limit(limit)
               .execute())

        # Reverse so oldest first for charts
        rows = list(reversed(res.data or []))

        return jsonify({
            "success": True,
            "plate": plate,
            "count": len(rows),
            "data": rows
        }), 200

    except Exception as e:
        print(f"[ERROR] api_obd_history: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/obd/stats", methods=["GET"])
def api_obd_stats():
    """Aggregate stats across all vehicles."""
    if not session.get("user_id"):
        return jsonify({"success": False, "error": "Not logged in."}), 401

    try:
        res = supabase.table("OBD_Data").select("*").order("Timestamp", desc=True).limit(1000).execute()
        rows = res.data or []

        if not rows:
            return jsonify({
                "success": True,
                "stats": {
                    "total_records": 0,
                    "active_vehicles": 0,
                    "total_distance_km": 0,
                    "total_fuel_burned_l": 0,
                    "avg_economy_kmL": 0,
                    "vehicles_running": 0
                }
            }), 200

        # Latest per plate
        latest = {}
        for r in rows:
            p = r.get("Plate_Number")
            if p and p not in latest:
                latest[p] = r

        latest_rows = list(latest.values())

        total_distance = sum(float(r.get("Distance_km") or 0) for r in latest_rows)
        total_fuel = sum(float(r.get("Fuel_Burned_L") or 0) for r in latest_rows)
        running = sum(1 for r in latest_rows if r.get("Engine_Running"))
        economy_values = [float(r.get("Inst_Economy_kmL") or 0) for r in latest_rows if r.get("Inst_Economy_kmL")]
        avg_economy = sum(economy_values) / len(economy_values) if economy_values else 0

        return jsonify({
            "success": True,
            "stats": {
                "total_records": len(rows),
                "active_vehicles": len(latest_rows),
                "total_distance_km": round(total_distance, 2),
                "total_fuel_burned_l": round(total_fuel, 2),
                "avg_economy_kmL": round(avg_economy, 2),
                "vehicles_running": running
            }
        }), 200

    except Exception as e:
        print(f"[ERROR] api_obd_stats: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/obd/stream", methods=["GET"])
def api_obd_stream():
    """
    Server-Sent Events (SSE) — pushes latest data every 3 seconds.
    Usage: new EventSource('/api/obd/stream')
    """
    if not session.get("user_id"):
        return jsonify({"success": False, "error": "Not logged in."}), 401

    plate = request.args.get("plate", "").strip()

    def event_stream():
        import time
        last_seen = {}
        while True:
            try:
                query = supabase.table("OBD_Data").select("*").order("Timestamp", desc=True).limit(200)
                if plate:
                    query = query.eq("Plate_Number", plate)
                res = query.execute()
                rows = res.data or []

                # Only send rows that are new since last fetch
                new_rows = []
                for r in rows:
                    key = f"{r.get('Plate_Number')}_{r.get('Timestamp')}"
                    if key not in last_seen:
                        new_rows.append(r)
                        last_seen[key] = True

                # Keep memory bounded
                if len(last_seen) > 5000:
                    last_seen.clear()

                payload = {
                    "type": "update",
                    "count": len(rows),
                    "new": new_rows[:50],  # cap per event
                    "data": rows[:50]
                }
                yield f"data: {json.dumps(payload)}\n\n"

            except Exception as e:
                yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"

            time.sleep(3)

    return Response(event_stream(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive"
    })

# ============================================================
# PRODUCT STORE API
# ============================================================

@app.route("/products")
def products_page():
    """Product listing page."""
    return render_template("products.html")


@app.route("/products/<slug>")
def product_detail_page(slug):
    """Product detail page."""
    return render_template("product_detail.html", slug=slug)


@app.route("/cart")
def cart_page():
    """Cart page."""
    if not session.get("user_id"):
        return redirect(url_for("auth_page"))
    return render_template("cart.html")


@app.route("/checkout")
def checkout_page():
    """Checkout page."""
    if not session.get("user_id"):
        return redirect(url_for("auth_page"))
    return render_template("checkout.html")


# ============================================================
# PRODUCT API
# ============================================================

@app.route("/api/products", methods=["GET"])
def api_products_list():
    """Return all active products."""
    try:
        category = request.args.get("category", "").strip()
        query = supabase.table("Product").select("*").eq("active", True)
        if category and category != "all":
            query = query.eq("category", category)
        res = query.order("created_at", desc=True).execute()

        return jsonify({"success": True, "products": res.data or []}), 200

    except Exception as e:
        print(f"[ERROR] api_products_list: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/products/<slug>", methods=["GET"])
def api_product_detail(slug):
    """Return a single product by slug."""
    try:
        res = supabase.table("Product").select("*").eq("slug", slug).limit(1).execute()
        if not res.data:
            return jsonify({"success": False, "error": "Product not found."}), 404

        return jsonify({"success": True, "product": res.data[0]}), 200

    except Exception as e:
        print(f"[ERROR] api_product_detail: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# CART — server-side session cart
# ============================================================

def _get_cart():
    """Get cart from session (list of {product_id, quantity})."""
    return session.get("cart", [])


def _save_cart(cart):
    """Save cart to session."""
    session["cart"] = cart
    session.modified = True


@app.route("/api/cart", methods=["GET"])
def api_cart_get():
    """Return current cart with product details."""
    cart = _get_cart()

    if not cart:
        return jsonify({"success": True, "items": [], "subtotal": 0, "count": 0}), 200

    try:
        product_ids = [item["product_id"] for item in cart]
        res = supabase.table("Product").select("*").in_("id", product_ids).execute()
        products = {p["id"]: p for p in (res.data or [])}

        items = []
        subtotal = 0
        count = 0

        for item in cart:
            p = products.get(item["product_id"])
            if not p:
                continue
            line_total = float(p["price"]) * item["quantity"]
            subtotal += line_total
            count += item["quantity"]
            items.append({
                "product_id": p["id"],
                "name": p["name"],
                "slug": p["slug"],
                "price": float(p["price"]),
                "image_url": p.get("image_url"),
                "quantity": item["quantity"],
                "line_total": round(line_total, 2),
            })

        return jsonify({
            "success": True,
            "items": items,
            "subtotal": round(subtotal, 2),
            "count": count,
        }), 200

    except Exception as e:
        print(f"[ERROR] api_cart_get: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/cart/add", methods=["POST"])
def api_cart_add():
    """Add a product to the cart."""
    data = request.get_json(silent=True) or {}
    product_id = data.get("product_id")
    quantity = int(data.get("quantity", 1))

    if not product_id or quantity < 1:
        return jsonify({"success": False, "error": "Invalid product or quantity."}), 400

    try:
        # Verify product exists
        res = supabase.table("Product").select("id").eq("id", product_id).limit(1).execute()
        if not res.data:
            return jsonify({"success": False, "error": "Product not found."}), 404

        cart = _get_cart()

        # Update existing or append
        found = False
        for item in cart:
            if item["product_id"] == product_id:
                item["quantity"] += quantity
                found = True
                break
        if not found:
            cart.append({"product_id": product_id, "quantity": quantity})

        _save_cart(cart)

        count = sum(i["quantity"] for i in cart)
        return jsonify({"success": True, "message": "Added to cart.", "count": count}), 200

    except Exception as e:
        print(f"[ERROR] api_cart_add: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/cart/update", methods=["POST"])
def api_cart_update():
    """Update the quantity of a cart item."""
    data = request.get_json(silent=True) or {}
    product_id = data.get("product_id")
    quantity = int(data.get("quantity", 1))

    if not product_id:
        return jsonify({"success": False, "error": "Product ID required."}), 400

    cart = _get_cart()

    if quantity <= 0:
        cart = [i for i in cart if i["product_id"] != product_id]
    else:
        for item in cart:
            if item["product_id"] == product_id:
                item["quantity"] = quantity
                break

    _save_cart(cart)
    count = sum(i["quantity"] for i in cart)
    return jsonify({"success": True, "count": count}), 200


@app.route("/api/cart/remove", methods=["POST"])
def api_cart_remove():
    """Remove an item from the cart."""
    data = request.get_json(silent=True) or {}
    product_id = data.get("product_id")

    if not product_id:
        return jsonify({"success": False, "error": "Product ID required."}), 400

    cart = [i for i in _get_cart() if i["product_id"] != product_id]
    _save_cart(cart)

    count = sum(i["quantity"] for i in cart)
    return jsonify({"success": True, "count": count}), 200


@app.route("/api/cart/clear", methods=["POST"])
def api_cart_clear():
    """Empty the cart."""
    _save_cart([])
    return jsonify({"success": True, "count": 0}), 200


# ============================================================
# ORDERS — checkout
# ============================================================

@app.route("/api/orders/create", methods=["POST"])
def api_order_create():
    """Create an order from the current cart."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "Not logged in."}), 401

    data = request.get_json(silent=True) or {}
    customer_name = (data.get("customer_name") or "").strip()
    customer_email = (data.get("customer_email") or "").strip()
    customer_phone = (data.get("customer_phone") or "").strip()
    shipping_address = (data.get("shipping_address") or "").strip()
    notes = (data.get("notes") or "").strip()

    if not all([customer_name, customer_email, customer_phone, shipping_address]):
        return jsonify({"success": False, "error": "All required fields must be filled."}), 400

    cart = _get_cart()
    if not cart:
        return jsonify({"success": False, "error": "Cart is empty."}), 400

    try:
        # Fetch product details
        product_ids = [i["product_id"] for i in cart]
        res = supabase.table("Product").select("*").in_("id", product_ids).execute()
        products = {p["id"]: p for p in (res.data or [])}

        # Compute totals
        items = []
        subtotal = 0
        for item in cart:
            p = products.get(item["product_id"])
            if not p:
                continue
            line_total = float(p["price"]) * item["quantity"]
            subtotal += line_total
            items.append({
                "product_id": p["id"],
                "product_name": p["name"],
                "price": float(p["price"]),
                "quantity": item["quantity"],
                "line_total": round(line_total, 2),
            })

        tax = round(subtotal * 0.06, 2)          # 6% SST (Malaysia)
        shipping = 0 if subtotal >= 500 else 25  # free shipping over RM 500
        total = round(subtotal + tax + shipping, 2)

        # Create order
        order_number = f"OBD-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"

        order_payload = {
            "user_id": user_id,
            "order_number": order_number,
            "status": "pending",
            "subtotal": round(subtotal, 2),
            "tax": tax,
            "shipping": shipping,
            "total": total,
            "customer_name": customer_name,
            "customer_email": customer_email,
            "customer_phone": customer_phone,
            "shipping_address": shipping_address,
            "notes": notes,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        order_res = supabase.table("Order").insert(order_payload).execute()
        if not order_res.data:
            return jsonify({"success": False, "error": "Failed to create order."}), 500

        order = order_res.data[0]
        order_id = order["id"]

        # Insert order items
        for item in items:
            item["order_id"] = order_id

        if items:
            supabase.table("OrderItem").insert(items).execute()

        # Clear cart
        _save_cart([])

        log_activity(user_id, "order_created", {
            "order_number": order_number,
            "total": total,
            "items": len(items)
        })

        return jsonify({
            "success": True,
            "message": "Order placed successfully.",
            "order": {
                "id": order_id,
                "order_number": order_number,
                "total": total,
                "status": "pending"
            }
        }), 201

    except Exception as e:
        print(f"[ERROR] api_order_create: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/orders", methods=["GET"])
def api_orders_list():
    """List the current user's orders."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "Not logged in."}), 401

    try:
        res = (supabase.table("Order")
               .select("*")
               .eq("user_id", user_id)
               .order("created_at", desc=True)
               .execute())

        return jsonify({"success": True, "orders": res.data or []}), 200

    except Exception as e:
        print(f"[ERROR] api_orders_list: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/orders/<order_id>", methods=["GET"])
def api_order_detail(order_id):
    """Get a single order with its items."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "Not logged in."}), 401

    try:
        order_res = (supabase.table("Order")
                     .select("*")
                     .eq("id", order_id)
                     .eq("user_id", user_id)
                     .limit(1)
                     .execute())

        if not order_res.data:
            return jsonify({"success": False, "error": "Order not found."}), 404

        items_res = supabase.table("OrderItem").select("*").eq("order_id", order_id).execute()

        return jsonify({
            "success": True,
            "order": order_res.data[0],
            "items": items_res.data or []
        }), 200

    except Exception as e:
        print(f"[ERROR] api_order_detail: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.context_processor
def inject_session():
    return dict(session=session) 
# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({"success": False, "error": "Not found."}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"success": False, "error": "Server error."}), 500


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)