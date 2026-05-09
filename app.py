from flask import Flask, render_template, request, redirect, session, flash, jsonify, make_response, url_for

from flask_mail import Mail, Message
import sqlite3
import bcrypt
import random
import config
# from email.mime.text import MIMEText
# import smtplib
import os
from werkzeug.utils import secure_filename
import razorpay
import traceback
from utils.pdf_generator import generate_pdf
from datetime import datetime
from pytz import timezone


razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)



app = Flask(__name__)
app.secret_key = config.SECRET_KEY
@app.route('/')
def Home():
    if 'user_id' in session:
        return redirect('/user-dashboard')
    return redirect('/user-login')

# ---------------- EMAIL CONFIGURATION ----------------
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD



mail = Mail(app)
# ================= EMAIL CONTROL =================
EMAIL_ENABLED = True

def safe_send_mail(message, otp=None, label="MAIL"):

    try:
        mail.send(message)
        print(f"{label} SENT SUCCESSFULLY")

    except Exception as e:

        print(f"{label} FAILED")
        print("ERROR:", str(e))

        raise e


app.config['PRODUCT_UPLOAD_FOLDER'] = 'static/uploads/product_images'
app.config['PROFILE_UPLOAD_FOLDER'] = 'static/uploads/profile_images'

os.makedirs(app.config['PRODUCT_UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROFILE_UPLOAD_FOLDER'], exist_ok=True)

# ---------------- SQLITE DB CONNECTION FUNCTION --------------
def get_db_connection():
    # For PythonAnywhere, keep smartcart.db in same folder as app.py
    db_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "smartcart.db"
    )

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    return conn


SUPERADMIN_EMAIL = "smartcartcompany1@gmail.com"



# ---------------------------------------------------------
# ROUTE 1: ADMIN SIGNUP (SEND OTP)
# ---------------------------------------------------------
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():

    # Show form
    if request.method == "GET":
        return render_template("admin/admin_signup.html", hide_admin_nav=True)

    # POST → Process signup
    name = request.form['name']
    email = request.form['email']

    # 1️⃣ Check if admin email already exists
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT admin_id FROM admin WHERE email=?", (email,))
    existing_admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if existing_admin:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect('/admin-signup')

    # 2️⃣ Save user input temporarily in session
    session['signup_name'] = name
    session['signup_email'] = email

    # 3️⃣ Generate OTP and store in session
    otp = random.randint(100000, 999999)
    session['otp'] = otp

    # 4️⃣ Send OTP Email
    message = Message(
        subject="SmartCart Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for SmartCart Admin Registration is: {otp}"
    safe_send_mail(message, otp, "ADMIN SIGNUP OTP")

    flash("OTP generated successfully! Check server log.", "success")
    return redirect('/verify-otp')


@app.route('/verify-otp', methods=['GET'])
def verify_otp_get():
    return render_template("admin/verify_otp.html", hide_admin_nav=True)

def send_admin_approval_mail(admin_id, name, email):

    approve_link = f"https://balanjineyulusmartcart.pythonanywhere.com/superadmin/approve-admin/{admin_id}"

    reject_link = f"https://balanjineyulusmartcart.pythonanywhere.com/superadmin/reject-admin/{admin_id}"

    message = Message(
        subject="New Admin Approval Request",
        sender=config.MAIL_USERNAME,
        recipients=[SUPERADMIN_EMAIL]
    )

    message.body = f"""
New Admin Registration Request

Name: {name}
Email: {email}

Approve:
{approve_link}

Reject:
{reject_link}
"""

    safe_send_mail(message, label="ADMIN APPROVAL MAIL")
#==============================================================
# ADMIN-VERIFY OTP Route
#==============================================================
@app.route('/verify-otp', methods=['POST'])
def verify_otp_post():
    
    user_otp = request.form['otp']
    password = request.form['password']

    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/verify-otp')

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO admin (name, email, password, status) VALUES (?, ?, ?, ?)",
        (session['signup_name'], session['signup_email'], hashed_password, 'pending')
    )

    conn.commit()

    admin_id = cursor.lastrowid
    admin_name = session['signup_name']
    admin_email = session['signup_email']

    cursor.close()
    conn.close()

    send_admin_approval_mail(admin_id, admin_name, admin_email)

    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("Admin Registered Successfully! Please wait for Super Admin approval.", "success")
    return redirect('/admin-login')

# =================================================================
# ROUTE 4: ADMIN LOGIN PAGE (GET + POST)
# =================================================================
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    if request.method == 'GET':
        return render_template("admin/admin_login.html", hide_admin_nav=True)

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admin WHERE email=?", (email,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if admin is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/admin-login')

    stored_hashed_password = admin['password'].encode('utf-8')

    if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
        flash("Incorrect password! Try again.", "danger")
        return redirect('/admin-login')

    if admin['status'] == 'pending':
        flash("Your account is waiting for Super Admin approval.", "warning")
        return redirect('/admin-login')

    if admin['status'] == 'rejected':
        flash("Your admin registration was rejected.", "danger")
        return redirect('/admin-login')

    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']
    session['admin_email'] = admin['email']

    flash("Login Successful!", "success")
    return redirect('/admin-dashboard')



# =================================================================
# ROUTE 5: ADMIN DASHBOARD (PROTECTED ROUTE)
# =================================================================
@app.route('/admin-dashboard')
def admin_dashboard():

    # Protect dashboard → Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login to access dashboard!", "danger")
        return redirect('/admin-login')

    # Send admin name to dashboard UI
    return render_template("admin/dashboard.html", admin_name=session['admin_name'])



# =================================================================
# ROUTE 6: ADMIN LOGOUT
# =================================================================
@app.route('/admin-logout')
def admin_logout():

    # Clear admin session
    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)

    flash("Logged out successfully.", "success")
    return redirect('/admin-login')


# # ------------------- IMAGE UPLOAD PATH -------------------
# UPLOAD_FOLDER = 'static/uploads/product_images'
# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# =================================================================
# ROUTE 7: SHOW ADD PRODUCT PAGE (Protected Route)
# =================================================================
@app.route('/admin/add-item', methods=['GET'])
def add_item_page():

    # Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    return render_template("admin/add_item.html")


# =================================================================
# ROUTE 8: ADD PRODUCT INTO DATABASE
# =================================================================
@app.route('/admin/add-item', methods=['POST'])
def add_item():

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    # 🔥 GET ADMIN ID FROM SESSION
    admin_id = session['admin_id']

    # 1️⃣ Get form data
    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    image_file = request.files['image']

    # 2️⃣ Validate image upload
    if image_file.filename == "":
        flash("Please upload a product image!", "danger")
        return redirect('/admin/add-item')

    # 3️⃣ Secure the file name
    filename = secure_filename(image_file.filename)

    # 4️⃣ Create full path
    image_path = os.path.join(app.config['PRODUCT_UPLOAD_FOLDER'], filename)

    # 5️⃣ Save image into folder
    image_file.save(image_path)

    # 6️⃣ Insert product into database (🔥 UPDATED)
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO products (name, description, category, price, image, admin_id)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (name, description, category, price, filename, admin_id)
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product added successfully!", "success")
    return redirect('/admin/add-item')

# =================================================================
# ROUTE 9: DISPLAY ALL PRODUCTS (Admin)
# =================================================================
@app.route('/admin/item-list')
def item_list():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1️⃣ Fetch category list only for this admin's products
    cursor.execute(
        "SELECT DISTINCT category FROM products WHERE admin_id = ?",
        (admin_id,)
    )
    categories = cursor.fetchall()

    # 2️⃣ Build dynamic query based on filters
    query = "SELECT * FROM products WHERE admin_id = ?"
    params = [admin_id]

    if search:
        query += " AND name LIKE ?"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    query += " ORDER BY product_id DESC"

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        categories=categories
    )




#=================================================================
# ROUTE 10: VIEW SINGLE PRODUCT DETAILS
# =================================================================
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
    "SELECT * FROM products WHERE product_id = ? AND admin_id = ?",
    (item_id, session['admin_id'])
)
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/view_item.html", product=product)

# =================================================================
# ROUTE 11: SHOW UPDATE FORM WITH EXISTING DATA
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    # Check login
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # Fetch product data
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
    "SELECT * FROM products WHERE product_id = ? AND admin_id = ?",
    (item_id, session['admin_id'])
)
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/update_item.html", product=product)

# =================================================================
# ROUTE-12: UPDATE PRODUCT + OPTIONAL IMAGE REPLACE
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # 1️⃣ Get updated form data
    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']

    new_image = request.files['image']

    # 2️⃣ Fetch old product data
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM products WHERE product_id = ? AND admin_id = ?",
        (item_id, session['admin_id'])
    )

    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    old_image_name = product['image']

    # 3️⃣ If admin uploaded a new image → replace it
    if new_image and new_image.filename != "":

        from werkzeug.utils import secure_filename

        # Secure filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        new_image_path = os.path.join(
            app.config['PRODUCT_UPLOAD_FOLDER'],
            new_filename
        )

        new_image.save(new_image_path)

        # Delete old image
        old_image_path = os.path.join(
            app.config['PRODUCT_UPLOAD_FOLDER'],
            old_image_name
        )

        if os.path.exists(old_image_path):
            os.remove(old_image_path)

        final_image_name = new_filename

    else:
        # Keep old image
        final_image_name = old_image_name

    # 4️⃣ Update product in database
    cursor.execute("""
        UPDATE products
        SET 
            name=?,
            description=?,
            category=?,
            price=?,
            image=?
        WHERE product_id=? AND admin_id=?
    """, (
        name,
        description,
        category,
        price,
        final_image_name,
        item_id,
        session['admin_id']
    ))

    conn.commit()

    cursor.close()
    conn.close()

    flash("Product updated successfully!", "success")

    return redirect('/admin/item-list')

# =================================================================
#  route-13 DELETE PRODUCT (DELETE DB ROW + DELETE IMAGE FILE)
# =================================================================
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']   # 🔥 ADD THIS

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1️⃣ Fetch product ONLY if it belongs to this admin
    cursor.execute(
        "SELECT image FROM products WHERE product_id=? AND admin_id=?",
        (item_id, admin_id)
    )
    product = cursor.fetchone()

    if not product:
        flash("Unauthorized or product not found!", "danger")
        return redirect('/admin/item-list')

    image_name = product['image']

    # Delete image from folder
    image_path = os.path.join(app.config['PRODUCT_UPLOAD_FOLDER'], image_name)
    if os.path.exists(image_path):
        os.remove(image_path)

    # 2️⃣ Delete product ONLY for this admin
    cursor.execute(
        "DELETE FROM products WHERE product_id=? AND admin_id=?",
        (item_id, admin_id)
    )
    conn.commit()

    cursor.close()
    conn.close()

    flash("Product deleted successfully!", "success")
    return redirect('/admin/item-list')

ADMIN_UPLOAD_FOLDER = 'static/uploads/admin_profiles'
app.config['ADMIN_UPLOAD_FOLDER'] = ADMIN_UPLOAD_FOLDER
os.makedirs(app.config['ADMIN_UPLOAD_FOLDER'], exist_ok=True)

# =================================================================
# ROUTE 14: SHOW ADMIN PROFILE DATA
# =================================================================
@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("admin/admin_profile.html", admin=admin)

# =================================================================
# ROUTE 15: UPDATE ADMIN PROFILE (NAME, EMAIL, PASSWORD, IMAGE)
# =================================================================
@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    # 1️⃣ Get form data
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files['profile_image']

    conn = get_db_connection()
    cursor = conn.cursor()

    # 2️⃣ Fetch old admin data
    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()

    old_image_name = admin['profile_image']

    # 3️⃣ Update password only if entered
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    else:
        hashed_password = admin['password']  # keep old password

    # 4️⃣ Process new profile image if uploaded
    if new_image and new_image.filename != "":
        
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        # Delete old image
        if old_image_name:
            old_image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # 5️⃣ Update database
    cursor.execute("""
        UPDATE admin
        SET name=?, email=?, password=?, profile_image=?
        WHERE admin_id=?
    """, (name, email, hashed_password, final_image_name, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    # Update session name for UI consistency
    session['admin_name'] = name  
    session['admin_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')




@app.route('/about')
def about():
    return render_template(
        'admin/about.html',
        hide_admin_nav=True,
        hide_admin_footer=True   # 🔥 ADD THIS LINE
    )

#============================================================================================
#       CONTACT PAGE
#==========================================================================================

# =========================================================
# ADMIN CONTACT SUPERADMIN
# =========================================================
@app.route("/contact", methods=["GET", "POST"])
def contact():

    if request.method == "POST":

        name = request.form["name"]
        email = request.form["email"]
        phone = request.form["phone"]
        message_text = request.form["message"]

        try:

            msg = Message(
                subject="Contact Admin - SmartCart",
                sender=app.config['MAIL_USERNAME'],
                recipients=[SUPERADMIN_EMAIL]
            )

            msg.body = f"""
New Message From Admin

Name: {name}
Phone: {phone}
Email: {email}

Message:
{message_text}
"""

            safe_send_mail(msg)

            flash("Message sent successfully!", "success")

        except Exception as e:

            print("ADMIN CONTACT MAIL ERROR:", e)

            flash("Error sending message!", "danger")

        return redirect('/contact')

    return render_template(
        "admin/contact.html",
        hide_admin_nav=True
    )

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():

    if request.method == 'GET':
        return render_template("admin/forgot_password.html", hide_admin_nav=True)

    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin WHERE email=?", (email,))
    admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if not admin:
        flash("Email not found!", "danger")
        return redirect('/forgot-password')

    otp = random.randint(100000, 999999)

    session['reset_email'] = email
    session['reset_otp'] = str(otp)

    try:
        msg = Message(
            subject="Password Reset OTP",
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )

        msg.body = f"Your OTP is: {otp}"

        safe_send_mail(msg)

        flash("OTP sent successfully to your email!", "success")
        return redirect('/verify-reset-otp')

    except Exception as e:
        print("ADMIN RESET MAIL ERROR:", e)
        flash("Failed to send OTP email!", "danger")
        return redirect('/forgot-password')

# VERIFY OTP ROUTE
@app.route('/verify-reset-otp', methods=['GET', 'POST'])
def verify_reset_otp():

    if request.method == 'GET':
        return render_template("admin/verify_reset_otp.html", hide_admin_nav=True)

    user_otp = request.form['otp']

    if user_otp != session.get('reset_otp'):
        flash("Invalid OTP!", "danger")
        return redirect('/verify-reset-otp')

    flash("OTP Verified! Now reset your password.", "success")
    return redirect('/reset-password')

#RESET PASSWORD
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():

    if request.method == 'GET':
        return render_template("admin/reset_password.html", hide_admin_nav=True)

    new_password = request.form['password']

    # Hash password
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Update DB
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE admin SET password=? WHERE email=?",
        (hashed_password, session.get('reset_email'))
    )
    conn.commit()
    cursor.close()
    conn.close()

    # Clear session
    session.pop('reset_email', None)
    session.pop('reset_otp', None)

    flash("Password updated successfully!", "success")
    return redirect('/admin-login')

# ======================j==================================
# ADMIN: VIEW ALL ORDERS
# ======================j==================================
@app.route('/admin/orders')
def admin_orders():

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            o.order_id,
            o.user_id,
            COALESCE(u.name, o.full_name) AS username,
            o.full_name,
            o.phone,
            o.amount,
            o.payment_status,
            o.order_status,
            o.created_at,
            GROUP_CONCAT(DISTINCT oi.product_name) AS ordered_items
        FROM orders o
        JOIN order_items oi ON o.order_id = oi.order_id
        JOIN products p ON oi.product_id = p.product_id
        LEFT JOIN users u ON o.user_id = u.user_id
        WHERE p.admin_id = ?
        GROUP BY o.order_id
        ORDER BY o.order_id DESC
    """, (admin_id,))

    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("admin/order_list.html", orders=orders)

# ================================================================
# ADMIN: VIEW ORDER DETAILS
# ================================================================
@app.route('/admin/order/<int:order_id>')
def admin_order_details(order_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            o.*,
            u.name AS username,
            u.email AS user_email
        FROM orders o
        LEFT JOIN users u ON o.user_id = u.user_id
        WHERE o.order_id = ?
    """, (order_id,))
    order = cursor.fetchone()

    cursor.execute("""
        SELECT 
            oi.id,
            oi.order_id,
            oi.product_id,
            oi.product_name,
            oi.quantity,
            oi.price,
            oi.total
        FROM order_items oi
        JOIN products p ON oi.product_id = p.product_id
        WHERE oi.order_id = ?
        AND p.admin_id = ?
    """, (order_id, admin_id))

    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order or not items:
        flash("Order not found for your products!", "danger")
        return redirect('/admin/orders')

    return render_template("admin/order_details.html", order=order, items=items)


# ================================================================
# ADMIN: UPDATE ORDER STATUS
# ================================================================
@app.route("/admin/update-order-status/<int:order_id>", methods=['POST'])
def update_order_status(order_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']
    new_status = request.form.get('status')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT o.order_id
        FROM orders o
        JOIN order_items oi ON o.order_id = oi.order_id
        JOIN products p ON oi.product_id = p.product_id
        WHERE o.order_id = ?
        AND p.admin_id = ?
        LIMIT 1
    """, (order_id, admin_id))

    allowed_order = cursor.fetchone()

    if not allowed_order:
        cursor.close()
        conn.close()
        flash("You cannot update this order!", "danger")
        return redirect('/admin/orders')

    cursor.execute("""
        UPDATE orders
        SET order_status = ?
        WHERE order_id = ?
    """, (new_status, order_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Order status updated successfully!", "success")
    return redirect(f"/admin/order/{order_id}")





# ---------------------------------------- USER MODULE --------------------------------------------------------
# =================================================================
# ROUTE 01: USER REGISTRATION
# =================================================================
@app.route('/user-register', methods=['GET', 'POST'])
def user_register():

    if request.method == "GET":
        return render_template("user/user_register.html", hide_admin_nav=True)

    name = request.form['name']
    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT user_id FROM users WHERE email=?", (email,))
    existing_user = cursor.fetchone()

    cursor.close()
    conn.close()

    if existing_user:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect('/user-register')

    session['signup_name'] = name
    session['signup_email'] = email

    otp = random.randint(100000, 999999)
    session['otp'] = otp

    message = Message(
        subject="SmartCart User OTP",
        sender=app.config['MAIL_USERNAME'],
        recipients=[email]
    )

    message.body = f"""
Hello {name},

Your SmartCart OTP is:

{otp}

Use this OTP to complete your registration.

Thank You,
SmartCart Team
"""

    try:
        safe_send_mail(message)
        flash("OTP sent successfully to your email!", "success")
        return redirect('/user-verify-otp')

    except Exception as e:
        print("MAIL ERROR:", e)
        flash("Failed to send OTP email!", "danger")
        return redirect('/user-register')


@app.route('/user-verify-otp', methods=['GET'])
def user_verify_otp_get():
    return render_template("user/user_verify_otp.html")


# admin-VERIFY Route

@app.route('/user-verify-otp', methods=['POST'])
def user_verify_otp_post():
    
    # User submitted OTP + Password
    user_otp = request.form['otp']
    password = request.form['password']

    # Compare OTP
    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/user-verify-otp')

    # Hash password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Insert admin into database
    conn = get_db_connection()
    cursor = conn.cursor()
    # admin_id = session.get('admin_id') 
    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        (session['signup_name'], session['signup_email'], hashed_password)
    )
    conn.commit()
    cursor.close()
    conn.close()

    # Clear temporary session data
    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("User Registered Successfully!", "success")
    return redirect('/user-login')


# =================================================================
# ROUTE 02: USER LOGIN
# =================================================================
@app.route('/user-login', methods=['GET', 'POST'])
def user_login():
        # 🔥 ADD THIS
    if 'user_id' in session:
        return redirect('/user-dashboard')

    if request.method == 'GET':
        return render_template("user/user_login.html", hide_user_nav=True)

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        flash("Email not found! Please register.", "danger")
        return redirect('/user-login')

    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        flash("Incorrect password!", "danger")
        return redirect('/user-login')

    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    flash("Login successful!", "success")
    return redirect('/user-dashboard')
# =================================================================
# ROUTE 03: USER DASHBOARD
# =================================================================
# @app.context_processor
# def inject_cart_count():
#     cart = session.get('cart', {})
#     cart_count = sum(item['quantity'] for item in cart.values())
#     return dict(cart_count=cart_count)


@app.route('/user-dashboard')
def user_dashboard():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    # Example dashboard values
    total_orders = 12
    wishlist_count = 5
    available_offers = 3
    recent_views = 8

    return render_template(
        "user/user_home.html",
        user_name=session['user_name'],
        total_orders=total_orders,
        wishlist_count=wishlist_count,
        available_offers=available_offers,
        recent_views=recent_views
    )

# =================================================================
# ROUTE 04: USER LOGOUT
# =================================================================
@app.route('/user-logout')
def user_logout():
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect('/user-login')
# =================================================================
# ROUTE: USER PRODUCT LISTING (SEARCH + FILTER)
# =================================================================
@app.route('/user/products')
def user_products():

    if 'user_id' not in session:
        flash("Please login to view products!", "danger")
        return redirect('/user-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Categories only from active products of approved admins
    cursor.execute("""
        SELECT DISTINCT p.category
        FROM products p
        JOIN admin a ON p.admin_id = a.admin_id
        WHERE p.status = 'active'
        AND a.status = 'approved'
    """)
    categories = cursor.fetchall()

    # Show only active products from approved admins
    query = """
        SELECT p.*
        FROM products p
        JOIN admin a ON p.admin_id = a.admin_id
        WHERE p.status = 'active'
        AND a.status = 'approved'
    """
    params = []

    if search:
        query += " AND p.name LIKE ?"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND p.category = ?"
        params.append(category_filter)

    query += " ORDER BY p.product_id DESC"

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/user_products.html",
        products=products,
        categories=categories
    )
# =================================================================
# ROUTE: USER PRODUCT DETAILS PAGE
# =================================================================
@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM products WHERE product_id = ?", (product_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    return render_template("user/product_details.html", product=product)

#USER FORGOT PASSWORD

@app.route('/user-forgot-password', methods=['GET', 'POST'])
def user_forgot_password():

    if request.method == 'GET':
        return render_template("user/user_forgot_password.html", hide_user_nav=True)

    email = request.form['email']

    # Check email exists
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if not admin:
        flash("Email not found!", "danger")
        return redirect('/user-forgot-password')

    # Generate OTP
    otp = random.randint(100000, 999999)

    # Store in session
    session['reset_email'] = email
    session['reset_otp'] = str(otp)

    # Send email
    msg = Message(
        subject="Password Reset OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    msg.body = f"Your OTP is: {otp}"
    safe_send_mail(msg, otp, "USER RESET OTP")

    flash("OTP generated successfully! Check server log.", "success")
    return redirect('/user-verify-reset-otp')

# VERIFY OTP ROUTE
@app.route('/user-verify-reset-otp', methods=['GET', 'POST'])
def user_verify_reset_otp():

    if request.method == 'GET':
        return render_template("user/user_verify_reset_otp.html", hide_user_nav=True)

    user_otp = request.form['otp']

    if user_otp != session.get('reset_otp'):
        flash("Invalid OTP!", "danger")
        return redirect('/user-verify-reset-otp')

    flash("OTP Verified! Now reset your password.", "success")
    return redirect('/user-reset-password')

#RESET PASSWORD
@app.route('/user-reset-password', methods=['GET', 'POST'])
def user_reset_password():

    if request.method == 'GET':
        return render_template("user/user_reset_password.html", hide_user_nav=True)

    new_password = request.form['password']

    # Hash password
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Update DB
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET password=? WHERE email=?",
        (hashed_password, session.get('reset_email'))
    )
    conn.commit()
    cursor.close()
    conn.close()

    # Clear session
    session.pop('reset_email', None)
    session.pop('reset_otp', None)

    flash("Password updated successfully!", "success")
    return redirect('/user-login')

# UPLOAD_FOLDER = 'static/uploads/user_profiles'
# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# =================================================================
# ROUTE : SHOW USER PROFILE
# =================================================================
@app.route('/user/profile', methods=['GET'])
def user_profile():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("user/user_profile.html", user=user)


# =================================================================
# ROUTE : UPDATE USER PROFILE
# =================================================================
@app.route('/user/profile', methods=['POST'])
def user_profile_update():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    # 1️⃣ Get form data
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()

    # 2️⃣ Fetch old user data
    cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()

    # ================= IMAGE UPLOAD =================
    profile_image = user['profile_image']  # default old image

    if 'profile_image' in request.files:
        file = request.files['profile_image']

        if file and file.filename != "":
            filename = secure_filename(file.filename)

            # make unique filename
            filename = f"{user_id}_{filename}"

            # ✅ FIX: create folder if not exists
            upload_folder = app.config['PROFILE_UPLOAD_FOLDER']
            os.makedirs(upload_folder, exist_ok=True)

            filepath = os.path.join(upload_folder, filename)
            file.save(filepath)

            profile_image = filename

    # ================= PASSWORD =================
    if new_password:
        hashed_password = bcrypt.hashpw(
            new_password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')
    else:
        hashed_password = user['password']

    # ================= UPDATE DB =================
    cursor.execute("""
        UPDATE users
        SET name=?, email=?, password=?, profile_image=?
        WHERE user_id=?
    """, (name, email, hashed_password, profile_image, user_id))

    conn.commit()
    cursor.close()
    conn.close()

    # ================= SESSION UPDATE =================
    session['user_name'] = name
    session['user_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/user/profile')


# =================================================================
# ABOUT PAGE
# =================================================================
@app.route('/user-about')
def user_about():
    return render_template('user/user_about.html', hide_user_nav=True)



#==================================
#  ROUTE :user- CONTACT PAGE
#===================================

@app.route('/user-contact', methods=['GET', 'POST'])
def user_contact():

    if request.method == 'POST':
        name = request.form['name']
        phone = request.form['phone']
        email = request.form['email']
        message_text = request.form['message']

        try:
            msg = Message(
                subject="User Contact Message - SmartCart",
                sender=app.config['MAIL_USERNAME'],
                recipients=[SUPERADMIN_EMAIL]
            )

            msg.body = f"""
Name: {name}
Phone: {phone}
Email: {email}

Message:
{message_text}
"""

            safe_send_mail(msg)

            flash("Message sent successfully!", "success")

        except Exception as e:
            print("USER CONTACT MAIL ERROR:", e)
            flash("Error sending message!", "danger")

        return redirect('/user-contact')

    return render_template('user/user_contact.html')




# =================================================================
# CONTEXT PROCESSOR FOR CART COUNT
# =================================================================
@app.context_processor
def inject_cart_count():

    if 'user_id' not in session:
        return dict(cart_count=0)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*) AS count
        FROM cart
        WHERE user_id = ?
    """, (session['user_id'],))

    result = cursor.fetchone()

    cursor.close()
    conn.close()

    return dict(cart_count=result['count'] if result else 0)
# =================================================================
# ADD ITEM TO CART
# =================================================================
@app.route('/user/add-to-cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM products WHERE product_id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        cursor.close()
        conn.close()
        flash("Product not found.", "danger")
        return redirect(request.referrer or '/user/products')

    cursor.execute("""
        SELECT * FROM cart
        WHERE user_id = ? AND product_id = ?
    """, (user_id, product_id))

    existing_item = cursor.fetchone()

    if existing_item:
        cursor.execute("""
            UPDATE cart
            SET quantity = quantity + 1
            WHERE user_id = ? AND product_id = ?
        """, (user_id, product_id))
    else:
        cursor.execute("""
            INSERT INTO cart (user_id, product_id, quantity)
            VALUES (?, ?, 1)
        """, (user_id, product_id))

    conn.commit()

    # 🔥 🔥 IMPORTANT PART (ADD THIS)
    # Sync DB cart → session cart

    cursor.execute("""
        SELECT c.*, p.name, p.price, p.image
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.user_id = ?
    """, (user_id,))

    cart_items = cursor.fetchall()

    session_cart = {}

    for item in cart_items:
        pid = str(item['product_id'])   # 🔥 FIX KEY TYPE

        session_cart[pid] = {
            "product_id": pid,
            "name": item['name'],
            "price": item['price'],
            "quantity": item['quantity'],
            "image": item['image']
        }

    session['cart'] = session_cart
    # 🔥 🔥 END FIX

    cursor.close()
    conn.close()

    flash("Item added to cart!", "success")
    return redirect(request.referrer or '/user/products')
# =================================================================
# VIEW CART PAGE
# =================================================================
@app.route('/user/cart', methods=['GET', 'POST'])
def view_cart():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            cart.cart_id,
            cart.product_id,
            cart.quantity,
            products.name,
            products.price,
            products.image,
            products.category,
            (cart.quantity * products.price) AS total
        FROM cart
        JOIN products ON cart.product_id = products.product_id
        WHERE cart.user_id = ?
    """, (user_id,))

    cart_items = cursor.fetchall()

    grand_total = sum(float(item['total']) for item in cart_items)
    cart_count = len(cart_items)

    selected_products = []
    selected_total = 0

    if request.method == 'POST':
        selected_products = request.form.getlist('selected_products')

        for item in cart_items:
            if str(item['product_id']) in selected_products:
                selected_total += float(item['total'])

    cursor.close()
    conn.close()

    return render_template(
        "user/cart.html",
        cart_items=cart_items,
        grand_total=grand_total,
        cart_count=cart_count,
        selected_total=selected_total,
        selected_products=selected_products
    )


# =================================================================
# INCREASE QUANTITY
# =================================================================
@app.route('/user/cart/increase/<int:pid>')
def increase_quantity(pid):

    if 'user_id' not in session:
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE cart
        SET quantity = quantity + 1
        WHERE user_id = ? AND product_id = ?
    """, (user_id, pid))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/user/cart')

# =================================================================
# DECREASE QUANTITY
# =================================================================
@app.route('/user/cart/decrease/<int:pid>')
def decrease_quantity(pid):

    if 'user_id' not in session:
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT quantity FROM cart
        WHERE user_id = ? AND product_id = ?
    """, (user_id, pid))

    item = cursor.fetchone()

    if item:
        if item['quantity'] > 1:
            cursor.execute("""
                UPDATE cart
                SET quantity = quantity - 1
                WHERE user_id = ? AND product_id = ?
            """, (user_id, pid))
        else:
            cursor.execute("""
                DELETE FROM cart
                WHERE user_id = ? AND product_id = ?
            """, (user_id, pid))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/user/cart')

# =================================================================
# REMOVE ITEM
# =================================================================
@app.route('/user/cart/remove/<int:pid>')
def remove_from_cart(pid):

    if 'user_id' not in session:
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM cart
        WHERE user_id = ? AND product_id = ?
    """, (user_id, pid))

    conn.commit()

    print("Deleted rows:", cursor.rowcount)  # 🔥 DEBUG

    cursor.close()
    conn.close()

    flash("Item removed!", "success")
    return redirect('/user/cart')
# =================================================================
# ROUTE: CREATE RAZORPAY ORDER
# =================================================================

@app.route('/user/pay')
def user_pay():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    if 'shipping_address_id' not in session:
        flash("Please select shipping address first!", "warning")
        return redirect('/user/shipping-address')

    selected_items = session.get('selected_products_checkout', {})
    selected_total = session.get('selected_products_total', 0)
    cart = session.get('cart', {})

    if selected_items:
        total_amount = float(selected_total)
    elif cart:
        total_amount = sum(float(item['price']) * int(item['quantity']) for item in cart.values())
    else:
        flash("Your cart is empty!", "danger")
        return redirect('/user/products')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM addresses WHERE address_id = ? AND user_id = ?",
        (session['shipping_address_id'], session['user_id'])
    )
    shipping_address = cursor.fetchone()

    cursor.close()
    conn.close()

    if not shipping_address:
        flash("Shipping address not found!", "danger")
        return redirect('/user/shipping-address')

    razorpay_amount = int(total_amount * 100)

    razorpay_order = razorpay_client.order.create({
        "amount": razorpay_amount,
        "currency": "INR",
        "payment_capture": "1"
    })

    session['razorpay_order_id'] = razorpay_order['id']

    return render_template(
        "user/payment.html",
        amount=total_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id'],
        shipping_address=shipping_address
    )

#-----------------------------------------
#route for selected products
#-----------------------------------------
@app.route('/user/pay-selected-products', methods=['POST'])
def pay_selected_products():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']
    selected_products = request.form.getlist('selected_products')

    if not selected_products:
        flash("Please select at least one product.", "warning")
        return redirect('/user/cart')

    conn = get_db_connection()
    cursor = conn.cursor()

    selected_items = {}
    selected_total = 0

    for pid in selected_products:
        cursor.execute("""
            SELECT c.quantity, p.product_id, p.name, p.price, p.image, p.admin_id
            FROM cart c
            JOIN products p ON c.product_id = p.product_id
            WHERE c.user_id = ? AND c.product_id = ?
        """, (user_id, pid))

        item = cursor.fetchone()

        if item:
            selected_items[str(item['product_id'])] = dict(item)
            selected_total += float(item['price']) * int(item['quantity'])

    cursor.close()
    conn.close()

    if not selected_items:
        flash("Invalid product selection.", "danger")
        return redirect('/user/cart')

    session['selected_products_checkout'] = selected_items
    session['selected_products_total'] = selected_total

    return redirect('/user/shipping-address')

#----------------------------------------------------------------
# ROUTE: SHIPPING ADDRESS
#---------------------------------------------------------------
@app.route('/user/shipping-address', methods=['GET', 'POST'])
def shipping_address():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':

        action = request.form.get("action")

        if action == "use_existing":

            selected_address_id = request.form.get('selected_address_id')

            if not selected_address_id:
                cursor.close()
                conn.close()
                flash("Please select an address!", "warning")
                return redirect('/user/shipping-address')

            cursor.execute(
                "SELECT address_id FROM addresses WHERE address_id = ? AND user_id = ?",
                (selected_address_id, user_id)
            )
            address = cursor.fetchone()

            if not address:
                cursor.close()
                conn.close()
                flash("Invalid address selected!", "danger")
                return redirect('/user/shipping-address')

            session['shipping_address_id'] = address['address_id']

            cursor.close()
            conn.close()

            return redirect('/user/pay')

        elif action == "save_new":

            full_name = request.form.get("full_name")
            phone = request.form.get("phone")
            address1 = request.form.get("address_line1")
            address2 = request.form.get("address_line2")
            city = request.form.get("city")
            state = request.form.get("state")
            pincode = request.form.get("pincode")
            country = request.form.get("country") or "India"

            if not full_name or not phone or not address1:
                cursor.close()
                conn.close()
                flash("Please fill required fields!", "warning")
                return redirect('/user/shipping-address')

            cursor.execute("""
                INSERT INTO addresses
                (user_id, full_name, phone, address_line1, address_line2, city, state, pincode, country)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, full_name, phone, address1, address2, city, state, pincode, country))

            conn.commit()

            session['shipping_address_id'] = cursor.lastrowid

            cursor.close()
            conn.close()

            flash("Address saved successfully!", "success")
            return redirect('/user/pay')

    cursor.execute(
        "SELECT * FROM addresses WHERE user_id = ? ORDER BY address_id DESC",
        (user_id,)
    )
    addresses = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/shipping_address.html", addresses=addresses)

# ------------------------------
# Route: Verify Payment and Store Order
# ------------------------------
@app.route('/verify-payment', methods=['POST'])
def verify_payment():

    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user-login')

    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    payload = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }

    try:
        razorpay_client.utility.verify_payment_signature(payload)
    except Exception as e:
        app.logger.error("Razorpay verification failed: %s", str(e))
        flash("Payment verification failed.", "danger")
        return redirect('/user/cart')

    user_id = session['user_id']
    shipping_address_id = session.get('shipping_address_id')

    if not shipping_address_id:
        flash("Shipping address missing.", "danger")
        return redirect('/user/shipping-address')

    conn = get_db_connection()
    cursor = conn.cursor()

    try:

        # INDIA TIME
        india = timezone('Asia/Kolkata')
        created_at = datetime.now(india).strftime("%Y-%m-%d %H:%M:%S")

        # Get address
        cursor.execute("""
            SELECT * FROM addresses
            WHERE address_id = ? AND user_id = ?
        """, (shipping_address_id, user_id))

        address = cursor.fetchone()

        if not address:
            flash("Invalid address.", "danger")
            return redirect('/user/shipping-address')

        # Get cart items
        selected_products_dict = session.get('selected_products_checkout', {})

        if selected_products_dict:
            cart_items = []

            for item in selected_products_dict.values():
                cart_items.append({
                    'product_id': item['product_id'],
                    'quantity': int(item['quantity']),
                    'name': item['name'],
                    'price': float(item['price']),
                    'admin_id': item.get('admin_id', 1)
                })
        else:
            cursor.execute("""
                SELECT 
                    cart.product_id,
                    cart.quantity,
                    products.name,
                    products.price,
                    products.admin_id
                FROM cart
                JOIN products 
                    ON cart.product_id = products.product_id
                WHERE cart.user_id = ?
            """, (user_id,))

            cart_items = [dict(row) for row in cursor.fetchall()]

        if not cart_items:
            flash("No items found for checkout.", "danger")
            return redirect('/user/products')

        # Total amount
        total_amount = sum(
            float(item['price']) * int(item['quantity'])
            for item in cart_items
        )

        # First product admin
        admin_id = cart_items[0].get('admin_id')

        # Insert order
        cursor.execute("""
            INSERT INTO orders (
                user_id,
                razorpay_order_id,
                razorpay_payment_id,
                amount,
                payment_status,
                order_status,
                full_name,
                phone,
                address_line1,
                address_line2,
                city,
                state,
                pincode,
                country,
                admin_id,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            razorpay_order_id,
            razorpay_payment_id,
            total_amount,
            'paid',
            'Pending',
            address['full_name'],
            address['phone'],
            address['address_line1'],
            address['address_line2'],
            address['city'],
            address['state'],
            address['pincode'],
            address['country'],
            admin_id,
            created_at
        ))

        order_db_id = cursor.lastrowid

        # Insert order items
        for item in cart_items:

            quantity = int(item['quantity'])
            price = float(item['price'])
            total = quantity * price

            cursor.execute("""
                INSERT INTO order_items (
                    order_id,
                    product_id,
                    product_name,
                    quantity,
                    price,
                    total,
                    admin_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                order_db_id,
                item['product_id'],
                item['name'],
                quantity,
                price,
                total,
                item['admin_id']
            ))

        # Clear cart
        if selected_products_dict:

            for item in selected_products_dict.values():

                cursor.execute("""
                    DELETE FROM cart
                    WHERE user_id = ? AND product_id = ?
                """, (
                    user_id,
                    item['product_id']
                ))

        else:

            cursor.execute("""
                DELETE FROM cart
                WHERE user_id = ?
            """, (user_id,))

        # Clear session
        session.pop('cart', None)
        session.pop('selected_products_checkout', None)
        session.pop('selected_products_total', None)
        session.pop('razorpay_order_id', None)
        session.pop('shipping_address_id', None)

        conn.commit()

        flash("Payment successful! Order placed.", "success")

        return redirect(f'/user/order-success/{order_db_id}')

    except Exception as e:

        conn.rollback()

        print("ERROR:", str(e))

        flash("Order failed after payment!", "danger")

        return redirect('/user/cart')

    finally:

        cursor.close()
        conn.close()
#------------------------------------------------------------
# ROUTE: ORDER-SUCCESS
#-------------------------------------------------------
@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM orders WHERE order_id=? AND user_id=?", (order_db_id, session['user_id']))
    order = cursor.fetchone()

    cursor.execute("SELECT * FROM order_items WHERE order_id=?", (order_db_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/products')

    return render_template("user/order_success.html", order=order, items=items)

#-------------------------------------------
#    ROUTE: MY- ORDERS
#-------------------------------------------
@app.route('/user/my-orders')
def my_orders():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            order_id,
            user_id,
            amount,
            payment_status,
            order_status,
            created_at
        FROM orders
        WHERE user_id = ?
        ORDER BY created_at DESC
    """, (user_id,))

    orders = cursor.fetchall()

    print("LOGGED USER ID:", user_id)
    print("ORDERS FOUND:", orders)

    cursor.close()
    conn.close()

    return render_template("user/my_orders.html", orders=orders)
#====================================================================================================
#    CANCEL ORDER
#====================================================================================================

@app.route('/user/cancel-order/<int:order_id>')
def cancel_order(order_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM orders
        WHERE order_id = ? AND user_id = ?
    """, (order_id, user_id))

    order = cursor.fetchone()

    if not order:
        flash("Order not found!", "danger")

    elif order['order_status'] == 'Cancelled':
        flash("Order already cancelled!", "warning")

    else:
        cursor.execute("""
            UPDATE orders
            SET order_status = 'Cancelled'
            WHERE order_id = ? AND user_id = ?
        """, (order_id, user_id))

        conn.commit()
        flash("Order cancelled successfully!", "success")

    cursor.close()
    conn.close()

    return redirect('/user/my-orders')


# ----------------------------
# GENERATE INVOICE PDF
# ----------------------------
@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    # Fetch order
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM orders WHERE order_id=? AND user_id=?",
                   (order_id, session['user_id']))
    order = cursor.fetchone()

    cursor.execute("SELECT * FROM order_items WHERE order_id=?", (order_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/my-orders')

    # Render invoice HTML
    html = render_template("user/invoice.html", order=order, items=items)

    pdf = generate_pdf(html)
    if not pdf:
        flash("Error generating PDF", "danger")
        return redirect('/user/my-orders')

    # Prepare response
    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f"attachment; filename=invoice_{order_id}.pdf"

    return response

#======================================== SUPER ADMIN MODULE ======================================================#
# ============================================================
# SUPER ADMIN REGISTER
# ============================================================
@app.route('/superadmin-register', methods=['GET', 'POST'])
def superadmin_register():

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM superadmins WHERE email = ?", (email,))
        existing_superadmin = cursor.fetchone()

        if existing_superadmin:
            flash("Super Admin already exists with this email!", "danger")
            cursor.close()
            conn.close()
            return redirect('/superadmin-register')

        # Hash password before saving
        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

        cursor.execute(
            "INSERT INTO superadmins (name, email, password) VALUES (?, ?, ?)",
            (name, email, hashed_password)
        )

        conn.commit()
        cursor.close()
        conn.close()

        flash("Super Admin registered successfully! Please login.", "success")
        return redirect('/superadmin-login')

    return render_template('superadmin/register.html', hide_superadmin_nav=True)

# ============================================================
# SUPER ADMIN LOGIN
# ============================================================
@app.route('/superadmin-login', methods=['GET', 'POST'])
def superadmin_login():

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM superadmins WHERE email = ?",
            (email,)
        )

        superadmin = cursor.fetchone()

        cursor.close()
        conn.close()

        if superadmin and bcrypt.checkpw(
            password.encode('utf-8'),
            superadmin['password'].encode('utf-8')
        ):
            session['superadmin_id'] = superadmin['superadmin_id']
            session['superadmin_name'] = superadmin['name']

            flash("Super Admin login successful!", "success")
            return redirect('/superadmin/dashboard')

        else:
            flash("Invalid Super Admin email or password!", "danger")
            return redirect('/superadmin-login')

    return render_template('superadmin/login.html', hide_superadmin_nav=True)
# ============================================================
# SUPER ADMIN LOGIN CHECK DECORATOR
# ============================================================
def superadmin_required():
    if 'superadmin_id' not in session:
        flash("Please login as Super Admin!", "danger")
        return False
    return True


# ============================================================
# SUPER ADMIN DASHBOARD
# ============================================================
@app.route('/superadmin/dashboard')
def superadmin_dashboard():

    if not superadmin_required():
        return redirect('/superadmin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS total_admins FROM admin")
    total_admins = cursor.fetchone()['total_admins']

    cursor.execute("SELECT COUNT(*) AS total_products FROM products")
    total_products = cursor.fetchone()['total_products']

    cursor.execute("""
        SELECT COUNT(*) AS total_orders
        FROM orders
        WHERE order_status != 'Cancelled'
    """)
    total_orders = cursor.fetchone()['total_orders']

    cursor.execute("""
        SELECT COALESCE(SUM(amount), 0) AS total_revenue
        FROM orders
        WHERE order_status != 'Cancelled'
    """)
    total_revenue = cursor.fetchone()['total_revenue']

    cursor.close()
    conn.close()

    return render_template(
        'superadmin/dashboard.html',
        total_admins=total_admins,
        total_products=total_products,
        total_orders=total_orders,
        total_revenue=total_revenue
    )

# ============================================================
# VIEW ALL ADMINS
# ============================================================
@app.route('/superadmin/admins')
def superadmin_admins():

    if not superadmin_required():
        return redirect('/superadmin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admin ORDER BY admin_id DESC")
    admins = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('superadmin/admins.html', admins=admins)

# ============================================================
# APPROVE ADMIN
# ============================================================
@app.route('/superadmin/approve-admin/<int:admin_id>')
def approve_admin(admin_id):

    if 'superadmin_id' not in session:
        flash("Please login as Super Admin!", "danger")
        return redirect('/superadmin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1️⃣ Approve admin
    cursor.execute("""
        UPDATE admin
        SET status = 'approved'
        WHERE admin_id = ?
    """, (admin_id,))

    # 2️⃣ Reactivate all products of this admin
    cursor.execute("""
        UPDATE products
        SET status = 'active'
        WHERE admin_id = ?
    """, (admin_id,))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Admin approved and products restored!", "success")
    return redirect('/superadmin/admins')


# ============================================================
# REJECT ADMIN
# ============================================================
@app.route('/superadmin/reject-admin/<int:admin_id>')
def reject_admin(admin_id):

    if 'superadmin_id' not in session:
        flash("Please login as Super Admin!", "danger")
        return redirect('/superadmin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1️⃣ Reject admin
    cursor.execute("""
        UPDATE admin
        SET status = 'rejected'
        WHERE admin_id = ?
    """, (admin_id,))

    # 2️⃣ Deactivate all products of this admin
    cursor.execute("""
        UPDATE products
        SET status = 'inactive'
        WHERE admin_id = ?
    """, (admin_id,))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Admin rejected and their products removed from user view!", "warning")
    return redirect('/superadmin/admins')

# ============================================================
# VIEW ALL PRODUCTS
# ============================================================
@app.route('/superadmin/products')
def superadmin_products():

    if not superadmin_required():
        return redirect('/superadmin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT products.*, admin.name AS admin_name
        FROM products
        LEFT JOIN admin ON products.admin_id = admin.admin_id
        ORDER BY products.product_id DESC
    """)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('superadmin/products.html', products=products)


# ============================================================
# VIEW ALL ORDERS
# ============================================================
@app.route('/superadmin/orders')
def superadmin_orders():

    if not superadmin_required():
        return redirect('/superadmin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            o.order_id,
            o.user_id,
            u.name AS username,
            o.amount,
            o.payment_status,
            o.order_status,
            o.created_at,
            GROUP_CONCAT(DISTINCT oi.product_name) AS products
        FROM orders o
        LEFT JOIN users u 
            ON o.user_id = u.user_id
        LEFT JOIN order_items oi 
            ON o.order_id = oi.order_id
        GROUP BY o.order_id
        ORDER BY o.order_id DESC
    """)

    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        'superadmin/orders.html',
        orders=orders
    )

@app.route('/superadmin/order/<int:order_id>')
def superadmin_order_details(order_id):

    if not superadmin_required():
        return redirect('/superadmin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # ORDER DETAILS
    cursor.execute("""
        SELECT 
            o.*,
            u.name AS username,
            u.email AS user_email
        FROM orders o
        LEFT JOIN users u
            ON o.user_id = u.user_id
        WHERE o.order_id = ?
    """, (order_id,))

    order = cursor.fetchone()

    # ORDER ITEMS
    cursor.execute("""
        SELECT *
        FROM order_items
        WHERE order_id = ?
    """, (order_id,))

    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found!", "danger")
        return redirect('/superadmin/orders')

    return render_template(
        'superadmin/order_details.html',
        order=order,
        items=items
    )

# ============================================================
# VIEW REVENUE
# ============================================================
@app.route('/superadmin/revenue')
def superadmin_revenue():

    if not superadmin_required():
        return redirect('/superadmin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # =========================
    # TOTAL REVENUE
    # Cancelled orders excluded
    # =========================
    cursor.execute("""
        SELECT 
            COALESCE(SUM(amount), 0) AS total_revenue
        FROM orders
        WHERE order_status != 'Cancelled'
    """)

    total_revenue = cursor.fetchone()['total_revenue']

    # =========================
    # ADMIN WISE REVENUE
    # Cancelled orders excluded
    # =========================
    cursor.execute("""
        SELECT 
            admin.name AS admin_name,

            COALESCE(SUM(order_items.total), 0) AS revenue

        FROM admin

        LEFT JOIN products
            ON admin.admin_id = products.admin_id

        LEFT JOIN order_items
            ON products.product_id = order_items.product_id

        LEFT JOIN orders
            ON order_items.order_id = orders.order_id

        WHERE (
            orders.order_status != 'Cancelled'
            OR orders.order_id IS NULL
        )

        GROUP BY admin.admin_id, admin.name

        ORDER BY revenue DESC
    """)

    admin_revenue = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        'superadmin/revenue.html',
        total_revenue=total_revenue,
        admin_revenue=admin_revenue
    )
#=========================================================
#      SUPER ADMIN FORGOT PASSWORD
#=====================================================

# =========================================================
# SUPERADMIN FORGOT PASSWORD
# =========================================================
@app.route('/sa-forgot-password', methods=['GET', 'POST'])
def sa_forgot_password():

    if request.method == 'GET':
        return render_template(
            "superadmin/sa_forgot_password.html",
            hide_superadmin_nav=True
        )

    email = request.form['email']

    # Check email exists
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM superadmins WHERE email=?",
        (email,)
    )

    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if not admin:
        flash("Email not found!", "danger")
        return redirect('/sa-forgot-password')

    # Generate OTP
    otp = random.randint(100000, 999999)

    # Store in session
    session['reset_email'] = email
    session['reset_otp'] = str(otp)

    try:
        # Send Email
        msg = Message(
            subject="Password Reset OTP",
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )

        msg.body = f"""
SmartCart SuperAdmin Password Reset

Your OTP is: {otp}

Do not share this OTP with anyone.
"""

        safe_send_mail(msg)

        flash("OTP sent successfully to your email!", "success")

    except Exception as e:
        print("MAIL ERROR:", e)
        flash("Failed to send OTP email. Please try again.", "danger")
        return redirect('/sa-forgot-password')

    return redirect('/sa-verify-reset-otp')


# =========================================================
# VERIFY RESET OTP
# =========================================================
@app.route('/sa-verify-reset-otp', methods=['GET', 'POST'])
def sa_verify_reset_otp():

    if 'reset_email' not in session:
        flash("Please enter your email first!", "warning")
        return redirect('/sa-forgot-password')

    if request.method == 'GET':
        return render_template(
            "superadmin/sa_verify_reset_otp.html",
            hide_superadmin_nav=True
        )

    user_otp = request.form['otp']

    if user_otp != session.get('reset_otp'):
        flash("Invalid OTP!", "danger")
        return redirect('/sa-verify-reset-otp')

    session['otp_verified'] = True

    flash("OTP verified successfully!", "success")

    return redirect('/sa-reset-password')


# =========================================================
# RESET PASSWORD
# =========================================================
@app.route('/sa-reset-password', methods=['GET', 'POST'])
def sa_reset_password():

    if 'reset_email' not in session:
        flash("Please start from forgot password!", "warning")
        return redirect('/sa-forgot-password')

    if not session.get('otp_verified'):
        flash("Please verify OTP first!", "warning")
        return redirect('/sa-verify-reset-otp')

    if request.method == 'GET':
        return render_template(
            "superadmin/sa_reset_password.html",
            hide_superadmin_nav=True
        )

    new_password = request.form['password']

    hashed_password = bcrypt.hashpw(
        new_password.encode('utf-8'),
        bcrypt.gensalt()
    ).decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE superadmins SET password=? WHERE email=?",
        (hashed_password, session['reset_email'])
    )

    conn.commit()

    cursor.close()
    conn.close()

    # Clear session
    session.pop('reset_email', None)
    session.pop('reset_otp', None)
    session.pop('otp_verified', None)

    flash("Password updated successfully!", "success")

    return redirect('/superadmin-login')

# ============================================================
# SUPER ADMIN LOGOUT
# ============================================================
@app.route('/superadmin/logout')
def superadmin_logout():
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect('/superadmin-login')


@app.route('/user/buy-now/<int:product_id>', methods=['POST', 'GET'])
def buy_now(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM products WHERE product_id = ?", (product_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    # Store only selected buy-now product in session
    session['selected_products_checkout'] = {
        str(product_id): {
            'product_id': product['product_id'],
            'name': product['name'],
            'price': float(product['price']),
            'quantity': 1,
            'image': product['image'],
            'category': product['category'],
            'admin_id': product['admin_id']
        }
    }

    session['selected_products_total'] = float(product['price'])

    # Optional: clear normal cart checkout session
    # session.pop('cart', None)

    # If address not selected, send to address page first
    if 'shipping_address_id' not in session:
        flash("Please select shipping address first!", "warning")
        return redirect('/user/shipping-address')

    # Directly go to Razorpay payment page
    return redirect('/user/pay')




@app.route('/user/delete-address/<int:address_id>')
def delete_address(address_id):

    if 'user_id' not in session:
        flash("Please login first.", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM addresses WHERE address_id=? AND user_id=?",
        (address_id, session['user_id'])
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Address deleted successfully.", "success")

    return redirect('/user/shipping-address')  # ✅ FIXED


@app.route('/user/edit-address/<int:address_id>', methods=['GET', 'POST'])
def edit_address(address_id):

    if 'user_id' not in session:
        flash("Please login first.", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # ✅ GET → Show existing data
    if request.method == 'GET':
        cursor.execute(
            "SELECT * FROM addresses WHERE address_id=? AND user_id=?",
            (address_id, session['user_id'])
        )
        address = cursor.fetchone()

        cursor.close()
        conn.close()

        if not address:
            flash("Address not found!", "danger")
            return redirect('/user/shipping-address')

        return render_template('user/edit_address.html', address=address)

    # ✅ POST → Update address
    full_name = request.form['full_name']
    phone = request.form['phone']
    address_line1 = request.form['address_line1']
    address_line2 = request.form['address_line2']
    city = request.form['city']
    state = request.form['state']
    pincode = request.form['pincode']
    country = request.form['country']

    cursor.execute("""
        UPDATE addresses
        SET full_name=?, phone=?, address_line1=?, address_line2=?,
            city=?, state=?, pincode=?, country=?
        WHERE address_id=? AND user_id=?
    """, (
        full_name, phone, address_line1, address_line2,
        city, state, pincode, country,
        address_id, session['user_id']
    ))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Address updated successfully!", "success")
    return redirect('/user/shipping-address')


@app.route('/admin/sales-report')
def admin_sales_report():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')

    if not from_date or not to_date:
        today = datetime.now().strftime('%Y-%m-%d')
        from_date = today
        to_date = today

    date_filter = " AND DATE(o.created_at) BETWEEN ? AND ?"
    params = [admin_id, from_date, to_date]

    conn = get_db_connection()
    cursor = conn.cursor()

    # =========================
    # DAILY SALES
    # =========================
    cursor.execute(f"""
        SELECT 
            DATE(o.created_at) AS sale_date,
            COALESCE(SUM(oi.total), 0) AS total_sales,
            COUNT(DISTINCT o.order_id) AS total_orders

        FROM orders o

        JOIN order_items oi 
            ON o.order_id = oi.order_id

        JOIN products p 
            ON oi.product_id = p.product_id

        WHERE p.admin_id = ?
        AND o.order_status != 'Cancelled'
        {date_filter}

        GROUP BY DATE(o.created_at)

        ORDER BY sale_date
    """, params)

    sales = cursor.fetchall()

    # =========================
    # SUMMARY
    # =========================
    cursor.execute(f"""
        SELECT 
            COALESCE(SUM(oi.total), 0) AS total_revenue,
            COUNT(DISTINCT o.order_id) AS total_orders

        FROM orders o

        JOIN order_items oi 
            ON o.order_id = oi.order_id

        JOIN products p 
            ON oi.product_id = p.product_id

        WHERE p.admin_id = ?
        AND o.order_status != 'Cancelled'
        {date_filter}
    """, params)

    summary = cursor.fetchone()

    # =========================
    # ORDER STATUS COUNTS
    # =========================
    def count_status(status):

        cursor.execute(f"""
            SELECT COUNT(DISTINCT o.order_id) AS total

            FROM orders o

            JOIN order_items oi 
                ON o.order_id = oi.order_id

            JOIN products p 
                ON oi.product_id = p.product_id

            WHERE p.admin_id = ?
            {date_filter}
            AND o.order_status = ?

        """, [admin_id, from_date, to_date, status])

        result = cursor.fetchone()

        return result["total"] or 0

    pending_orders = count_status("Pending")
    confirmed_orders = count_status("Confirmed")
    packed_orders = count_status("Packed")
    shipped_orders = count_status("Shipped")
    delivered_orders = count_status("Delivered")
    cancelled_orders = count_status("Cancelled")

    # =========================
    # PRODUCT SALES
    # =========================
    cursor.execute(f"""
        SELECT 
            p.product_id,
            p.name AS product_name,
            p.price,
            p.stock,

            COALESCE(SUM(oi.quantity), 0) AS sold_quantity,
            COALESCE(SUM(oi.total), 0) AS product_revenue

        FROM products p

        LEFT JOIN order_items oi 
            ON p.product_id = oi.product_id

        LEFT JOIN orders o 
            ON oi.order_id = o.order_id

        WHERE p.admin_id = ?

        AND (
            o.order_id IS NULL
            OR (
                DATE(o.created_at) BETWEEN ? AND ?
                AND o.order_status != 'Cancelled'
            )
        )

        GROUP BY 
            p.product_id,
            p.name,
            p.price,
            p.stock

        ORDER BY sold_quantity DESC
    """, params)

    product_sales = cursor.fetchall()

    highest_selling_product = product_sales[0] if product_sales else None
    lowest_selling_product = product_sales[-1] if product_sales else None

    # =========================
    # LOW STOCK PRODUCTS
    # =========================
    cursor.execute("""
        SELECT 
            product_id,
            name AS product_name,
            stock

        FROM products

        WHERE admin_id = ?

        ORDER BY stock ASC

        LIMIT 5
    """, (admin_id,))

    low_stock_products = cursor.fetchall()

    # =========================
    # HIGH STOCK PRODUCTS
    # =========================
    cursor.execute("""
        SELECT 
            product_id,
            name AS product_name,
            stock

        FROM products

        WHERE admin_id = ?

        ORDER BY stock DESC

        LIMIT 5
    """, (admin_id,))

    highest_stock_products = cursor.fetchall()

    cursor.close()
    conn.close()

    # =========================
    # DAILY SALES FORMAT
    # =========================
    daily_sales = []

    for row in sales:

        daily_sales.append({
            "date": str(row["sale_date"]),
            "orders": row["total_orders"],
            "revenue": float(row["total_sales"] or 0)
        })

    daily_labels = [row["date"] for row in daily_sales]
    daily_revenue = [row["revenue"] for row in daily_sales]

    # =========================
    # RENDER TEMPLATE
    # =========================
    return render_template(

        "admin/sales_report.html",

        from_date=from_date,
        to_date=to_date,

        total_revenue=float(summary["total_revenue"] or 0),
        total_orders=summary["total_orders"] or 0,

        pending_orders=pending_orders,
        confirmed_orders=confirmed_orders,
        packed_orders=packed_orders,
        shipped_orders=shipped_orders,
        completed_orders=delivered_orders,
        cancelled_orders=cancelled_orders,

        daily_sales=daily_sales,
        daily_labels=daily_labels,
        daily_revenue=daily_revenue,

        product_sales=product_sales,

        highest_selling_product=highest_selling_product,
        lowest_selling_product=lowest_selling_product,

        low_stock_products=low_stock_products,
        highest_stock_products=highest_stock_products
    )
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
from openpyxl.utils import get_column_letter
from io import BytesIO
from flask import make_response


@app.route('/admin/download-sales-excel')
def download_sales_excel():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')

    if not from_date or not to_date:
        today = datetime.now().strftime('%Y-%m-%d')
        from_date = today
        to_date = today

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            DATE(o.created_at) AS sale_date,
            o.order_id,
            oi.product_name,
            oi.quantity,
            oi.price,
            oi.total,
            o.order_status
        FROM orders o
        JOIN order_items oi ON o.order_id = oi.order_id
        JOIN products p ON oi.product_id = p.product_id
        WHERE p.admin_id = ?
        AND DATE(o.created_at) BETWEEN ? AND ?
        ORDER BY o.created_at DESC
    """, (admin_id, from_date, to_date))

    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    wb = Workbook()
    ws = wb.active
    ws.title = "Sales Report"

    ws.merge_cells("A1:G1")
    ws["A1"] = f"SmartCart Sales Report ({from_date} to {to_date})"
    ws["A1"].font = Font(size=16, bold=True, color="FFFFFF")
    ws["A1"].fill = PatternFill(start_color="0F172A", end_color="0F172A", fill_type="solid")
    ws["A1"].alignment = Alignment(horizontal="center")

    ws.append([])
    ws.append(["Date", "Order ID", "Product Name", "Quantity", "Price", "Total", "Status"])

    header_fill = PatternFill(start_color="2563EB", end_color="2563EB", fill_type="solid")
    header_font = Font(color="FFFFFF", bold=True)

    border = Border(
        left=Side(style="thin"),
        right=Side(style="thin"),
        top=Side(style="thin"),
        bottom=Side(style="thin")
    )

    for cell in ws[3]:
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center")
        cell.border = border

    total_revenue = 0
    total_orders = set()

    for row in rows:
        price = float(row['price'] or 0)
        total = float(row['total'] or 0)

        total_revenue += total
        total_orders.add(row['order_id'])

        ws.append([
            str(row['sale_date']),
            row['order_id'],
            row['product_name'],
            row['quantity'],
            price,
            total,
            row['order_status']
        ])

    for row_cells in ws.iter_rows(min_row=4):
        for cell in row_cells:
            cell.border = border
            cell.alignment = Alignment(horizontal="center")

    last_row = ws.max_row + 2

    ws.cell(row=last_row, column=5).value = "Total Orders"
    ws.cell(row=last_row, column=6).value = len(total_orders)

    ws.cell(row=last_row + 1, column=5).value = "Total Revenue"
    ws.cell(row=last_row + 1, column=6).value = total_revenue

    ws.cell(row=last_row, column=5).font = Font(bold=True)
    ws.cell(row=last_row, column=6).font = Font(bold=True)

    ws.cell(row=last_row + 1, column=5).font = Font(bold=True)
    ws.cell(row=last_row + 1, column=6).font = Font(bold=True)

    for col_num in range(1, ws.max_column + 1):
        max_length = 0
        col_letter = get_column_letter(col_num)

        for row_num in range(1, ws.max_row + 1):
            cell = ws.cell(row=row_num, column=col_num)

            if cell.value:
                max_length = max(max_length, len(str(cell.value)))

        ws.column_dimensions[col_letter].width = max_length + 3

    file_stream = BytesIO()
    wb.save(file_stream)
    file_stream.seek(0)

    response = make_response(file_stream.read())
    response.headers["Content-Disposition"] = f"attachment; filename=sales_report_{from_date}_to_{to_date}.xlsx"
    response.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    return response

@app.route('/superadmin/sales-report')
def superadmin_sales_report():

    if 'superadmin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/superadmin-login')

    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')

    if not from_date or not to_date:
        today = datetime.now().strftime('%Y-%m-%d')
        from_date = today
        to_date = today

    conn = get_db_connection()
    cursor = conn.cursor()

    # =========================
    # ADMIN WISE REVENUE
    # Cancelled orders excluded from revenue
    # =========================
    cursor.execute("""
        SELECT 
            a.admin_id,
            a.name AS admin_name,
            COUNT(DISTINCT o.order_id) AS total_orders,
            IFNULL(SUM(o.amount), 0) AS total_sales
        FROM admin a
        LEFT JOIN orders o 
            ON a.admin_id = o.admin_id
            AND DATE(o.created_at) BETWEEN ? AND ?
            AND o.order_status != 'Cancelled'
        GROUP BY a.admin_id, a.name
        ORDER BY total_sales DESC
    """, (from_date, to_date))

    admin_sales = cursor.fetchall()

    # =========================
    # DAILY SALES
    # Cancelled orders excluded
    # =========================
    cursor.execute("""
        SELECT 
            DATE(created_at) AS sale_date,
            COUNT(order_id) AS total_orders,
            IFNULL(SUM(amount), 0) AS total_revenue
        FROM orders
        WHERE DATE(created_at) BETWEEN ? AND ?
        AND order_status != 'Cancelled'
        GROUP BY DATE(created_at)
        ORDER BY sale_date
    """, (from_date, to_date))

    daily_sales_rows = cursor.fetchall()

    # =========================
    # ORDER STATUS COUNTS
    # Keep Cancelled count separate
    # =========================
    def count_status(status):
        cursor.execute("""
            SELECT COUNT(order_id) AS total
            FROM orders
            WHERE DATE(created_at) BETWEEN ? AND ?
            AND order_status = ?
        """, (from_date, to_date, status))

        result = cursor.fetchone()
        return result["total"] or 0

    pending_orders = count_status("Pending")
    confirmed_orders = count_status("Confirmed")
    packed_orders = count_status("Packed")
    shipped_orders = count_status("Shipped")
    delivered_orders = count_status("Delivered")
    cancelled_orders = count_status("Cancelled")

    # =========================
    # SUMMARY
    # Cancelled orders excluded from total revenue/orders
    # =========================
    cursor.execute("""
        SELECT 
            IFNULL(SUM(amount), 0) AS total_revenue,
            COUNT(order_id) AS total_orders
        FROM orders
        WHERE DATE(created_at) BETWEEN ? AND ?
        AND order_status != 'Cancelled'
    """, (from_date, to_date))

    summary = cursor.fetchone()

    cursor.close()
    conn.close()

    admin_labels = [row["admin_name"] for row in admin_sales]
    admin_revenue = [float(row["total_sales"] or 0) for row in admin_sales]

    daily_labels = [str(row["sale_date"]) for row in daily_sales_rows]
    daily_revenue = [float(row["total_revenue"] or 0) for row in daily_sales_rows]

    status_labels = [
        "Pending",
        "Confirmed",
        "Packed",
        "Shipped",
        "Delivered",
        "Cancelled"
    ]

    status_values = [
        pending_orders,
        confirmed_orders,
        packed_orders,
        shipped_orders,
        delivered_orders,
        cancelled_orders
    ]

    return render_template(
        "superadmin/sales_report.html",

        admin_sales=admin_sales,

        total_revenue=float(summary["total_revenue"] or 0),
        total_orders=summary["total_orders"] or 0,

        pending_orders=pending_orders,
        confirmed_orders=confirmed_orders,
        packed_orders=packed_orders,
        shipped_orders=shipped_orders,
        delivered_orders=delivered_orders,
        completed_orders=delivered_orders,
        cancelled_orders=cancelled_orders,

        admin_labels=admin_labels,
        admin_revenue=admin_revenue,

        daily_labels=daily_labels,
        daily_revenue=daily_revenue,

        status_labels=status_labels,
        status_values=status_values,

        from_date=from_date,
        to_date=to_date
    )
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
from openpyxl.utils import get_column_letter
from io import BytesIO
from flask import make_response


@app.route('/superadmin/download-sales-excel')
def superadmin_download_sales_excel():

    if 'superadmin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/superadmin-login')

    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')

    if not from_date or not to_date:
        today = datetime.now().strftime('%Y-%m-%d')
        from_date = today
        to_date = today

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            COUNT(DISTINCT order_id) AS total_orders,
            COALESCE(SUM(amount), 0) AS total_revenue
        FROM orders
        WHERE DATE(created_at) BETWEEN ? AND ?
    """, (from_date, to_date))
    summary = cursor.fetchone()

    cursor.execute("SELECT COUNT(*) AS total_admins FROM admin")
    admins_count = cursor.fetchone()

    cursor.execute("SELECT COUNT(*) AS total_products FROM products")
    products_count = cursor.fetchone()

    cursor.execute("SELECT COUNT(*) AS total_users FROM users")
    users_count = cursor.fetchone()

    cursor.execute("""
        SELECT 
            a.admin_id,
            a.name AS admin_name,
            a.email AS admin_email,
            COUNT(DISTINCT o.order_id) AS total_orders,
            COALESCE(SUM(oi.total), 0) AS total_revenue,
            COALESCE(SUM(oi.quantity), 0) AS total_items_sold
        FROM admin a
        LEFT JOIN products p 
            ON a.admin_id = p.admin_id
        LEFT JOIN order_items oi 
            ON p.product_id = oi.product_id
        LEFT JOIN orders o 
            ON oi.order_id = o.order_id
            AND DATE(o.created_at) BETWEEN ? AND ?
        GROUP BY a.admin_id, a.name, a.email
        ORDER BY total_revenue DESC
    """, (from_date, to_date))
    admin_sales = cursor.fetchall()

    cursor.execute("""
        SELECT 
            a.name AS admin_name,
            p.product_id,
            p.name AS product_name,
            p.category,
            COALESCE(SUM(oi.quantity), 0) AS quantity_sold,
            COALESCE(SUM(oi.total), 0) AS total_sales
        FROM products p
        LEFT JOIN admin a 
            ON p.admin_id = a.admin_id
        LEFT JOIN order_items oi 
            ON p.product_id = oi.product_id
        LEFT JOIN orders o 
            ON oi.order_id = o.order_id
            AND DATE(o.created_at) BETWEEN ? AND ?
        GROUP BY p.product_id, p.name, p.category, a.name
        ORDER BY total_sales DESC
    """, (from_date, to_date))
    high_sales = cursor.fetchall()

    cursor.execute("""
        SELECT 
            a.name AS admin_name,
            p.product_id,
            p.name AS product_name,
            p.category,
            p.stock,
            COALESCE(SUM(oi.quantity), 0) AS quantity_sold,
            COALESCE(SUM(oi.total), 0) AS total_sales
        FROM products p
        LEFT JOIN admin a 
            ON p.admin_id = a.admin_id
        LEFT JOIN order_items oi 
            ON p.product_id = oi.product_id
        LEFT JOIN orders o 
            ON oi.order_id = o.order_id
            AND DATE(o.created_at) BETWEEN ? AND ?
        GROUP BY p.product_id, p.name, p.category, p.stock, a.name
        ORDER BY total_sales ASC
    """, (from_date, to_date))
    low_sales = cursor.fetchall()

    cursor.execute("""
        SELECT 
            DATE(created_at) AS sale_date,
            COUNT(order_id) AS total_orders,
            COALESCE(SUM(amount), 0) AS total_revenue
        FROM orders
        WHERE DATE(created_at) BETWEEN ? AND ?
        GROUP BY DATE(created_at)
        ORDER BY sale_date DESC
    """, (from_date, to_date))
    daily_sales = cursor.fetchall()

    cursor.execute("""
        SELECT 
            order_status,
            COUNT(order_id) AS total_orders,
            COALESCE(SUM(amount), 0) AS total_amount
        FROM orders
        WHERE DATE(created_at) BETWEEN ? AND ?
        GROUP BY order_status
        ORDER BY total_orders DESC
    """, (from_date, to_date))
    status_report = cursor.fetchall()

    cursor.execute("""
        SELECT 
            a.name AS admin_name,
            a.email AS admin_email,
            o.order_id,
            DATE(o.created_at) AS order_date,
            o.payment_status,
            o.order_status,
            o.amount AS order_amount,
            oi.product_id,
            oi.product_name,
            oi.quantity,
            oi.price,
            oi.total AS item_total,
            p.category,
            p.stock
        FROM orders o
        JOIN order_items oi 
            ON o.order_id = oi.order_id
        LEFT JOIN products p 
            ON oi.product_id = p.product_id
        LEFT JOIN admin a 
            ON p.admin_id = a.admin_id
        WHERE DATE(o.created_at) BETWEEN ? AND ?
        ORDER BY o.created_at DESC
    """, (from_date, to_date))
    full_data = cursor.fetchall()

    cursor.close()
    conn.close()

    wb = Workbook()

    header_fill = PatternFill(
        start_color="0F172A",
        end_color="0F172A",
        fill_type="solid"
    )

    header_font = Font(
        color="FFFFFF",
        bold=True
    )

    border = Border(
        left=Side(style="thin"),
        right=Side(style="thin"),
        top=Side(style="thin"),
        bottom=Side(style="thin")
    )

    def style(ws):

        for cell in ws[1]:
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal="center")
            cell.border = border

        for row in ws.iter_rows(min_row=2):
            for cell in row:
                cell.border = border
                cell.alignment = Alignment(horizontal="center")

        for col_num in range(1, ws.max_column + 1):

            max_length = 0
            col_letter = get_column_letter(col_num)

            for row_num in range(1, ws.max_row + 1):

                cell = ws.cell(row=row_num, column=col_num)

                if cell.value:
                    max_length = max(max_length, len(str(cell.value)))

            ws.column_dimensions[col_letter].width = min(max_length + 3, 45)

    ws = wb.active
    ws.title = "Summary"

    ws.append(["Metric", "Value"])
    ws.append(["From Date", from_date])
    ws.append(["To Date", to_date])
    ws.append(["Total Revenue", float(summary["total_revenue"] or 0)])
    ws.append(["Total Orders", summary["total_orders"] or 0])
    ws.append(["Total Admins", admins_count["total_admins"] or 0])
    ws.append(["Total Products", products_count["total_products"] or 0])
    ws.append(["Total Users", users_count["total_users"] or 0])

    style(ws)

    ws = wb.create_sheet("Admin Sales")

    ws.append([
        "Admin ID",
        "Admin Name",
        "Admin Email",
        "Orders",
        "Items Sold",
        "Revenue"
    ])

    for r in admin_sales:
        ws.append([
            r["admin_id"],
            r["admin_name"],
            r["admin_email"],
            r["total_orders"],
            r["total_items_sold"],
            float(r["total_revenue"] or 0)
        ])

    style(ws)

    ws = wb.create_sheet("High Sales")

    ws.append([
        "Admin",
        "Product ID",
        "Product",
        "Category",
        "Qty Sold",
        "Revenue"
    ])

    for r in high_sales:
        ws.append([
            r["admin_name"],
            r["product_id"],
            r["product_name"],
            r["category"],
            r["quantity_sold"],
            float(r["total_sales"] or 0)
        ])

    style(ws)

    ws = wb.create_sheet("Low Sales")

    ws.append([
        "Admin",
        "Product ID",
        "Product",
        "Category",
        "Stock",
        "Qty Sold",
        "Revenue"
    ])

    for r in low_sales:
        ws.append([
            r["admin_name"],
            r["product_id"],
            r["product_name"],
            r["category"],
            r["stock"],
            r["quantity_sold"],
            float(r["total_sales"] or 0)
        ])

    style(ws)

    ws = wb.create_sheet("Daily Sales")

    ws.append([
        "Date",
        "Orders",
        "Revenue"
    ])

    for r in daily_sales:
        ws.append([
            str(r["sale_date"]),
            r["total_orders"],
            float(r["total_revenue"] or 0)
        ])

    style(ws)

    ws = wb.create_sheet("Order Status")

    ws.append([
        "Status",
        "Orders",
        "Amount"
    ])

    for r in status_report:
        ws.append([
            r["order_status"],
            r["total_orders"],
            float(r["total_amount"] or 0)
        ])

    style(ws)

    ws = wb.create_sheet("All Orders")

    ws.append([
        "Admin Name",
        "Admin Email",
        "Order ID",
        "Date",
        "Payment Status",
        "Order Status",
        "Order Amount",
        "Product ID",
        "Product",
        "Category",
        "Qty",
        "Price",
        "Item Total",
        "Current Stock"
    ])

    for r in full_data:
        ws.append([
            r["admin_name"],
            r["admin_email"],
            r["order_id"],
            str(r["order_date"]),
            r["payment_status"],
            r["order_status"],
            float(r["order_amount"] or 0),
            r["product_id"],
            r["product_name"],
            r["category"],
            r["quantity"],
            float(r["price"] or 0),
            float(r["item_total"] or 0),
            r["stock"]
        ])

    style(ws)

    stream = BytesIO()
    wb.save(stream)
    stream.seek(0)

    response = make_response(stream.read())

    response.headers["Content-Disposition"] = (
        f"attachment; filename=superadmin_sales_report_{from_date}_to_{to_date}.xlsx"
    )

    response.headers["Content-Type"] = (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

    return response

@app.route('/superadmin/categories')
def superadmin_categories():

    if not superadmin_required():
        return redirect('/superadmin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            category,
            COUNT(*) AS total_products
        FROM products
        WHERE category IS NOT NULL AND category != ''
        GROUP BY category
        ORDER BY category ASC
    """)

    categories = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('superadmin/categories.html', categories=categories)


@app.route('/superadmin/category-products/<category>')
def category_products(category):

    if not superadmin_required():
        return redirect('/superadmin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM products 
        WHERE category = ?
        ORDER BY product_id DESC
    """, (category,))

    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        'superadmin/category_products.html',
        products=products,
        category=category
    )
@app.route('/superadmin/view-product/<int:product_id>')
def superadmin_view_product(product_id):

    if not superadmin_required():
        return redirect('/superadmin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            products.*,
            admin.name AS admin_name,
            admin.email AS admin_email
        FROM products
        LEFT JOIN admin ON products.admin_id = admin.admin_id
        WHERE products.product_id = ?
    """, (product_id,))

    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/superadmin/products')

    return render_template("superadmin/view_product.html", product=product)



@app.route('/demo-user-login')
def demo_user_login():

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE email=?",
        ("smartcartdemo@gmail.com",)
    )

    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()

        flash("Demo account not found!", "danger")
        return redirect('/user-login')

    demo_user_id = user['user_id']

    # CLEAR OLD DEMO DATA
    cursor.execute(
        "DELETE FROM cart WHERE user_id=?",
        (demo_user_id,)
    )

    cursor.execute(
        "DELETE FROM addresses WHERE user_id=?",
        (demo_user_id,)
    )

    cursor.execute("""
        DELETE FROM order_items
        WHERE order_id IN (
            SELECT order_id FROM orders
            WHERE user_id=?
        )
    """, (demo_user_id,))

    cursor.execute(
        "DELETE FROM orders WHERE user_id=?",
        (demo_user_id,)
    )

    conn.commit()

    cursor.close()
    conn.close()

    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    flash("Welcome to SmartCart Live Demo!", "success")

    return redirect('/user-dashboard')

if __name__=="__main__":
    app.run(debug=True)
