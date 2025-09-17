import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash,session,jsonify
from pymongo import MongoClient
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import re
from flask import render_template, request, redirect, url_for, flash, abort, current_app
from bson.objectid import ObjectId
import re
# and that you created: rides_col = db["rides"], bookings_col = db["bookings"]

load_dotenv()  
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "carpool_db")
SECRET_KEY = os.getenv("SECRET_KEY", "secret-key")
app = Flask(__name__)
app.secret_key = SECRET_KEY
import os
from datetime import datetime
from uuid import uuid4
from werkzeug.utils import secure_filename
from flask import request, redirect, url_for, flash, current_app

# after you create `app = Flask(__name__)`
# configure upload folder and size limit
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024   # 10 MB per request (adjust as needed)

# ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# allowed file extensions
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

# MongoDB drivers collection handle


client = MongoClient(MONGO_URI)
db = client[DB_NAME]
messages_col = db["contact_messages"] 
users_col = db["users"]   # collection for registered users
drivers_col = db["drivers"]
bookings_col = db["bookings"]   # <-- 
rides_col = db["rides"]   #
@app.route("/")
def home():
    """Root route → load homepage"""
    return render_template("home.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/vehicles")
def vehicles():
    return render_template("vehicles.html")

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        message = request.form.get("message", "").strip()
        if not name or not email or not message:
            flash("Please fill in all fields.", "danger")
            return redirect(url_for("contact"))
        doc = {
            "name": name,
            "email": email,
            "message": message,
            "created_at": datetime.utcnow()
        }
        try:
            messages_col.insert_one(doc)
            flash("Message sent — thank you!", "success")
        except Exception as e:
            app.logger.error("MongoDB insert failed: %s", e)
            flash("Something went wrong. Please try again later.", "danger")

        return redirect(url_for("contact"))

    return render_template("contact.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """
    GET: show the registration form
    POST: validate, hash password, save user into MongoDB, flash & redirect
    """
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")

        # simple server-side validation
        if not name or not email or not phone or not password:
            flash("Please fill in all fields.", "danger")
            return redirect(url_for("register"))

        # check duplicate email
        if users_col.find_one({"email": email}):
            flash("Email already registered. Please sign in.", "danger")
            return redirect(url_for("register"))

        # hash the password before storing
        pw_hash = generate_password_hash(password)  # default: pbkdf2:sha256

        user_doc = {
            "name": name,
            "email": email,
            "phone": phone,
            "password": pw_hash,
            "created_at": datetime.utcnow()
        }

        try:
            users_col.insert_one(user_doc)
        except Exception as e:
            app.logger.error("Failed to create user: %s", e)
            flash("Internal error. Please try again later.", "danger")
            return redirect(url_for("register"))

        # optional: log user in by storing user_id in session
        # session['user_id'] = str(user_doc_id)  # uncomment if you want auto-login

        flash("Account created successfully. Please sign in.", "success")
        return redirect(url_for("signin"))

    # GET -> render register page
    return render_template("register.html")


# add these imports at the top if not already present
from werkzeug.security import check_password_hash
from flask import session

# helper: return current logged-in user document or None
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        from bson.objectid import ObjectId
        return users_col.find_one({"_id": ObjectId(uid)})
    except Exception:
        return None

# Signin route (add below your other routes)
@app.route("/signin", methods=["GET", "POST"])
def signin():
    """
    GET -> render signin page
    POST -> verify credentials (email or name), set session on success
    """
    if request.method == "POST":
        identifier = request.form.get("username", "").strip()   # could be email or username
        password = request.form.get("password", "")

        if not identifier or not password:
            flash("Please enter both username (or email) and password.", "danger")
            return redirect(url_for("signin"))

        # Try to find user by email first, then by name
        user = users_col.find_one({"email": identifier.lower()})
        if not user:
            user = users_col.find_one({"name": identifier})

        # No user found
        if not user:
            flash("No account found for the provided username/email.", "danger")
            return redirect(url_for("signin"))

        # Verify password
        stored_hash = user.get("password", "")
        if not stored_hash or not check_password_hash(stored_hash, password):
            flash("Invalid credentials. Please try again.", "danger")
            return redirect(url_for("signin"))

        # Success: store minimal info in session (do not store password)
        session.clear()
        session["user_id"] = str(user["_id"])
        session["user_name"] = user.get("name")
        session["user_email"] = user["email"]  # store their email
        flash("Signed in successfully.", "success")
        return redirect(url_for("dashboard"))

    # GET -> show signin form
    return render_template("signin.html")
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/ridehistory")
def ridehistory():
    return render_template("ridehistory.html")


places_list = [
    "Port Blair", "Wandoor", "Havelock Island", "Swaraj Dweep", "Neil Island", "Shaheed Dweep",
    "Diglipur", "Mayabunder", "Rangat", "Baratang", "Long Island", "Little Andaman",
    "Car Nicobar", "Campbell Bay", "Ross Island", "North Bay", "Cinque Island", "Jolly Buoy",
    "Barren Island", "Mount Harriet", "Chidiyatapu", "Wimberlygunj", "Laxmanpur", "Bharatpur"
]

@app.route("/api/places")
def api_places():
    """
    Simple autocomplete API.
    Query param: q (partial text). Returns JSON list of up to 10 matching place names.
    Case-insensitive, matches anywhere in the name.
    """
    q = request.args.get("q", "").strip().lower()
    if not q:
        return jsonify([])

    matches = [p for p in places_list if q in p.lower()]
    # optional: sort by startswith first, then others
    matches.sort(key=lambda s: (0 if s.lower().startswith(q) else 1, s))
    return jsonify(matches[:10])
@app.route("/book_rides", methods=["GET"])
def book_rides_page():
    # render the HTML shell — JS inside will read query params and call /api/search_rides
    return render_template("book_rides.html")

@app.route("/api/search_rides", methods=["POST"])
def api_search_rides():
    try:
        data = request.get_json() or {}
        pickup = (data.get("pickup") or "").strip()
        destination = (data.get("destination") or "").strip()
        try:
            passengers = int(data.get("passengers") or 1)
            if passengers < 1:
                passengers = 1
        except (ValueError, TypeError):
            passengers = 1

        female_drivers = bool(data.get("female_drivers"))

        query = {}
        if pickup:
            safe = re.escape(pickup)
            query["origin"] = {"$regex": safe, "$options": "i"}
        if destination:
            safe = re.escape(destination)
            query["destination"] = {"$regex": safe, "$options": "i"}

        query["seats_available"] = {"$gte": passengers}
        if female_drivers:
            query["driver_gender"] = "female"

        cursor = rides_col.find(query).sort("created_at", -1).limit(200)

        results = []
        for r in cursor:
            date_field = r.get("date")
            if isinstance(date_field, datetime):
                date_str = date_field.strftime("%Y-%m-%d %H:%M")
            else:
                date_str = str(date_field) if date_field else ""

            # NEW: include rating and rating_count (safe casting)
            rating = r.get("rating", 0)
            try:
                rating = float(rating)
            except Exception:
                rating = 0.0
            rating_count = r.get("rating_count", 0)
            try:
                rating_count = int(rating_count)
            except Exception:
                rating_count = 0

            results.append({
                "id": str(r.get("_id")),
                "origin": r.get("origin", ""),
                "destination": r.get("destination", ""),
                "driver_name": r.get("driver_name", "Driver"),
                "seats_available": int(r.get("seats_available", 0)),
                "seats_total": r.get("seats_total", ""),
                "date": date_str,
                "fare": r.get("fare", 0),
                "contact_number": r.get("contact_number", ""),
                "profile_pic": r.get("files", {}).get("driver_photo", ""),
                "vehicle_pic": r.get("files", {}).get("vehicle_photo", ""),
                "notes": r.get("notes", ""),
                "rating": rating,
                "rating_count": rating_count
            })

        return jsonify(results)
    except Exception as e:
        current_app.logger.exception("api_search_rides error: %s", e)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/forget_password")
def forget_password():
    return render_template("forget_password.html")

@app.route("/reset_password", methods=["POST"])
def reset_password():
    email = request.form.get("email").strip().lower()
    new_pass = request.form.get("new_password")
    confirm_pass = request.form.get("confirm_password")

    if not email or not new_pass or not confirm_pass:
        flash("Please fill in all fields", "danger")
        return redirect(url_for("forget_password"))

    if new_pass != confirm_pass:
        flash("Passwords do not match!", "danger")
        return redirect(url_for("forget_password"))


    hashed_pw = generate_password_hash(new_pass)
    result = users_col.update_one({"email": email}, {"$set": {"password": hashed_pw}})

    if result.matched_count == 0:
        flash("No user found with that email!", "danger")
        return redirect(url_for("forget_password"))

    flash("Password reset successful. Please log in.", "success")
    return redirect(url_for("signin"))
@app.route("/driver", methods=["GET", "POST"])
def driver_page():
    if request.method == "POST":
        # --- read text fields ---
        name = request.form.get("driver_name", "").strip()
        gender = request.form.get("gender", "").strip()
        phone = request.form.get("contact_number", "").strip()
        address = request.form.get("address", "").strip()
        dob = request.form.get("dob", "").strip()
        vehicle_type = request.form.get("vehicle_type", "").strip()
        license_plate = request.form.get("license_plate", "").strip()
        insurance_no = request.form.get("insurance_number", "").strip()
        reg_date = request.form.get("registration_date", "").strip()
        reg_no = request.form.get("registration_number", "").strip()
        reg_expiry = request.form.get("registration_expiry", "").strip()
        ins_provider = request.form.get("insurance_provider", "").strip()
        ins_expiry = request.form.get("insurance_expiry", "").strip()
        service_details = request.form.get("service_details", "").strip()

        # --- helper: safe date parse ---
        def parse_date(s):
            if not s:
                return None
            try:
                return datetime.fromisoformat(s)
            except Exception:
                return None

        # --- handle file uploads ---
        saved = {}
        file_keys = ["driver_photo", "vehicle_photo", "registration_photo", "insurance_document", "service_document"]
        for key in file_keys:
            f = request.files.get(key)
            if not f or not f.filename:
                continue
            if not allowed_file(f.filename):
                flash(f"Invalid file type for {key}.", "danger")
                return redirect(url_for("driver_page"))
            ext = f.filename.rsplit(".", 1)[1].lower()
            filename = secure_filename(f"{uuid4().hex}_{int(datetime.utcnow().timestamp())}.{ext}")
            path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            f.save(path)
            saved[key] = f"uploads/{filename}"

        # --- build MongoDB document ---
        doc = {
            "driver_name": name,
            "gender": gender,
            "contact_number": phone,
            "address": address,
            "dob": parse_date(dob),
            "vehicle": {
                "type": vehicle_type,
                "license_plate": license_plate,
                "insurance_number": insurance_no,
                "registration_number": reg_no,
                "registration_date": parse_date(reg_date),
                "registration_expiry": parse_date(reg_expiry)
            },
            "insurance": {
                "provider": ins_provider,
                "expiry": parse_date(ins_expiry)
            },
            "service_history": {"details": service_details},
            "files": saved,
            "created_at": datetime.utcnow()
        }

        # --- insert and respond ---
        try:
            drivers_col.insert_one(doc)
            flash("Driver info saved.", "success")
        except Exception as e:
            current_app.logger.exception("Insert failed: %s", e)
            flash("Failed to save driver info.", "danger")

        return redirect(url_for("driver_page"))

    # 👇 GET request → render driver.html
    return render_template("driver.html")
from pymongo import ReturnDocument
from flask import jsonify

@app.route("/api/book_ride", methods=["POST"])
def api_book_ride():
    """
    POST JSON:
    { "ride_id": "<mongo id>", "passengers": 1 }
    Requires user to be signed in (session['user_id']). If user not signed in, returns 401.
    Atomically checks seats_available >= passengers and decrements using find_one_and_update.
    Creates a booking document in `bookings` collection on success.
    """
    try:
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401

        data = request.get_json() or {}
        ride_id = data.get("ride_id")
        try:
            passengers = int(data.get("passengers") or 1)
            if passengers < 1:
                passengers = 1
        except (ValueError, TypeError):
            passengers = 1

        if not ride_id:
            return jsonify({"error": "ride_id required"}), 400

        from bson.objectid import ObjectId
        try:
            oid = ObjectId(ride_id)
        except Exception:
            return jsonify({"error": "invalid ride_id"}), 400

        # Atomically decrement seats if enough available
        filter_q = {"_id": oid, "seats_available": {"$gte": passengers}}
        update_q = {"$inc": {"seats_available": -passengers}}
        updated = rides_col.find_one_and_update(
            filter_q,
            update_q,
            return_document=ReturnDocument.AFTER
        )

        if not updated:
            # either ride not found or not enough seats
            return jsonify({"error": "Not enough seats or ride not found"}), 409

        # create booking record
        booking = {
            "ride_id": oid,
            "user_id": ObjectId(session["user_id"]),
            "passengers": passengers,
            "fare_per_person": updated.get("fare", 0),
            "total_fare": (updated.get("fare", 0) * passengers),
            "contact_number": updated.get("contact_number", ""),
            "driver_name": updated.get("driver_name", ""),
            "origin": updated.get("origin", ""),
            "destination": updated.get("destination", ""),
            "created_at": datetime.utcnow(),
            "status": "confirmed"
        }
        bookings_col.insert_one(booking)

        # return updated ride summary & booking id
        return jsonify({
            "success": True,
            "ride": {
                "id": str(updated["_id"]),
                "seats_available": updated["seats_available"]
            }
        })
    except Exception as e:
        current_app.logger.exception("api_book_ride error: %s", e)
        return jsonify({"error": "Internal server error"}), 500
from flask import render_template, request
@app.route("/ride_confirm", methods=["GET"])
def ride_confirm_page():
    ride_id = request.args.get("ride_id")
    passengers = request.args.get("passengers", "1")
    try:
        passengers = int(passengers)
        if passengers < 1: passengers = 1
    except Exception:
        passengers = 1

    if not ride_id:
        flash("Missing ride ID", "danger")
        return redirect(url_for("book_rides_page"))

    try:
        oid = ObjectId(ride_id)
    except Exception:
        flash("Invalid ride ID", "danger")
        return redirect(url_for("book_rides_page"))

    ride = rides_col.find_one({"_id": oid})
    if not ride:
        flash("Ride not found", "danger")
        return redirect(url_for("book_rides_page"))

    date_field = ride.get("date")
    if isinstance(date_field, datetime):
        date_str = date_field.strftime("%Y-%m-%d %H:%M")
    else:
        date_str = str(date_field) if date_field else ""

    # rating normalization
    rating = ride.get("rating", 0)
    try:
        rating = float(rating)
    except Exception:
        rating = 0.0

    rating_count = ride.get("rating_count", 0)
    try:
        rating_count = int(rating_count)
    except Exception:
        rating_count = 0

    # normalize file paths (optional; keeps previous normalization)
    def normalize_static_path(p):
        if not p:
            return None
        p = p.lstrip('/')
        if p.startswith('static/'):
            p = p[len('static/'):]
        return p

    files = ride.get("files", {}) or {}
    driver_photo_rel = normalize_static_path(files.get("driver_photo"))
    vehicle_photo_rel = normalize_static_path(files.get("vehicle_photo"))

    ride_ctx = {
        "id": str(ride["_id"]),
        "origin": ride.get("origin", ""),
        "destination": ride.get("destination", ""),
        "driver_name": ride.get("driver_name", ""),
        "seats_available": int(ride.get("seats_available", 0)),
        "seats_total": ride.get("seats_total", ""),
        "date": date_str,
        "fare": ride.get("fare", 0),
        "contact_number": ride.get("contact_number", ""),
        "notes": ride.get("notes", ""),
        "driver_gender": ride.get("driver_gender", ""),
        "vehicle": ride.get("vehicle", {}) or {},
        "files": {
            "driver_photo": driver_photo_rel,
            "vehicle_photo": vehicle_photo_rel
        },
        "rating": rating,
        "rating_count": rating_count,
        "created_at": ride.get("created_at")
    }
    return render_template("confirm_booking.html", ride=ride_ctx, default_passengers=passengers)

from pymongo import ReturnDocument

@app.route("/confirm_booking", methods=["POST"])
def confirm_booking():
    if "user_id" not in session:
        flash("Please sign in to book a ride.", "warning")
        return redirect(url_for("signin"))

    ride_id = request.form.get("ride_id")
    try:
        passengers = int(request.form.get("passengers") or 1)
        if passengers < 1:
            passengers = 1
    except Exception:
        passengers = 1

    payment_method = request.form.get("payment_method", "cash")  # e.g. "cash", "upi", "card"
    # payment_details is free-form (store only non-sensitive references)
    # for card, DO NOT store full card numbers — just last4 or a token (this sample stores only what user enters for demo)
    payment_details = request.form.get("payment_details", "").strip()

    if not ride_id:
        flash("Missing ride ID.", "danger")
        return redirect(url_for("book_rides_page"))

    try:
        oid = ObjectId(ride_id)
    except Exception:
        flash("Invalid ride ID.", "danger")
        return redirect(url_for("book_rides_page"))

    # Atomically decrement seats
    filter_q = {"_id": oid, "seats_available": {"$gte": passengers}}
    update_q = {"$inc": {"seats_available": -passengers}}
    updated = rides_col.find_one_and_update(filter_q, update_q, return_document=ReturnDocument.AFTER)

    if not updated:
        flash("Not enough seats available or ride not found.", "danger")
        return redirect(url_for("book_rides_page"))

    booking = {
        "ride_id": oid,
        "user_id": ObjectId(session["user_id"]),
        "passengers": passengers,
        "fare_per_person": updated.get("fare", 0),
        "total_fare": (updated.get("fare", 0) * passengers),
        "contact_number": updated.get("contact_number", ""),
        "driver_name": updated.get("driver_name", ""),
        "origin": updated.get("origin", ""),
        "destination": updated.get("destination", ""),
        "payment_method": payment_method,
        "payment_details": payment_details,
        "created_at": datetime.utcnow(),
        "status": "confirmed"
    }
    bookings_col.insert_one(booking)

    flash("Booking confirmed! Check Ride History for details.", "success")
    return redirect(url_for("ridehistory"))


if __name__ == "__main__":
    app.run(debug=True)