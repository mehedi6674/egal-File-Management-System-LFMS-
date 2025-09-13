import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, abort
from datetime import datetime, date

import MySQLdb.cursors
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename, safe_join
from functools import wraps
from threading import Thread
import smtplib, ssl
from email.message import EmailMessage
from itsdangerous import URLSafeTimedSerializer
import msal
import requests
from flask import send_file

new_hash = generate_password_hash("your_new_password")
print("Generated hash:", new_hash)

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Serializer for generating secure tokens
app.config['SECURITY_PASSWORD_SALT'] = 'a-very-secret-salt-for-passwords'
serializer = URLSafeTimedSerializer(app.secret_key)

# SMTP Configuration
SMTP_SERVER = ""
SMTP_PORT = 
SMTP_USER = ""
SMTP_PASSWORD = ""
# MSAL / SSO Configuration -
# IMPORTANT: Fill these values from your Azure AD App Registration
app.config['CLIENT_ID'] = "YOUR_AZURE_APP_CLIENT_ID"
app.config['CLIENT_SECRET'] = "YOUR_AZURE_APP_CLIENT_SECRET"
app.config['TENANT_ID'] = "YOUR_AZURE_APP_TENANT_ID"
app.config['AUTHORITY'] = f"https://login.microsoftonline.com/{app.config['TENANT_ID']}"
app.config['REDIRECT_PATH'] = "/get_token"  # The redirect URI configured in Azure
app.config['ENDPOINT'] = 'https://graph.microsoft.com/v1.0/me'  # MS Graph API endpoint
app.config['SCOPE'] = ["User.Read"]
# Add SSO domains. Any user with an email from these domains will be redirected to Microsoft login.
app.config['SSO_DOMAINS'] = ['petromaxlpg.com', 'shvenergy.com'] # Example: ['your_company.com']

# MySQL config - change according to your setup
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''  # your password
app.config['MYSQL_DB'] = 'new'

mysql = MySQL(app)

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'png', 'jpg', 'jpeg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
MAX_TOTAL_ATTACHMENT_SIZE = 2 * 1024 * 1024  # 2MB in bytes
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.context_processor
def utility_processor():
    """Injects the current year into all templates."""
    return dict(current_year=date.today().year)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
def is_total_upload_size_allowed(files, max_size):
        total_size = 0
        for file in files:
            file.seek(0, os.SEEK_END)
            total_size += file.tell()
            file.seek(0)  # Reset pointer for saving
        return total_size <= max_size

def send_email_async(app_instance, to_email, subject, body):
    """Sends an email in a background thread to avoid blocking the main request."""
    def send_in_thread(app, to_email, subject, body):
        with app.app_context():
            send_email(to_email, subject, body)
    
    thread = Thread(target=send_in_thread, args=[app_instance, to_email, subject, body])
    thread.start()

def send_email(to_email, subject, body):
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = to_email

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Secure the connection with TLS
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Failed to send email to {to_email}: {e}")
        return False

# --------- Security Headers ------------
@app.after_request
def add_security_headers(response):
    """
    Adds security headers to every response to enhance protection against
    common web vulnerabilities like XSS and clickjacking.
    """
    # Content Security Policy (CSP) to control which resources can be loaded.
    # This is a moderately strict policy. It allows resources from the same origin ('self')
    # and from the CDNs used by the application (Bootstrap, SHV Energy for the logo).
    # 'unsafe-inline' is required for inline styles and scripts present in the templates.
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://cdn.shvenergy.com; "
        "object-src 'none'; "
        "frame-ancestors 'none';"
    )
    response.headers['Content-Security-Policy'] = csp
    # Prevents the browser from interpreting files as a different MIME type.
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Prevents the page from being displayed in a frame (clickjacking protection).
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Enables the XSS filter in older browsers.
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response
# Login required decorator
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if role and session.get('role') != role and session.get('role') != 'admin':
                flash("Unauthorized access", "danger")
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Admin approval decorator
def admin_required(f):
    return login_required(role='admin')(f)

# --------- Routes ------------

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

import secrets
import string

def generate_password(length=10):
    characters = string.ascii_uppercase + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(characters) for _ in range(length))

@app.route('/register', methods=['GET', 'POST'])
def register():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Get supervisor list for dropdown
    cur.execute("SELECT name, email FROM users WHERE role IN ('supervisor', 'ceo', 'admin') AND is_approved = 1")

    supervisors = cur.fetchall()

    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        designation = request.form['designation']
        department = request.form['department']
        supervisor_name = request.form['supervisor_name']
        supervisor_email = request.form['supervisor_email']
        company = request.form['company']
        location = request.form['location']
        email = request.form['email']

        # Auto-generate secure password
        password = generate_password()
        hashed_password = generate_password_hash(password)

        # Check if email already exists
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        existing_user = cur.fetchone()
        if existing_user:
            flash('Email already registered', 'danger')
            return render_template('register.html', supervisors=supervisors)

        cur.execute("""
            INSERT INTO users (
                name, designation, department, supervisor_name, supervisor_email,
                company, location, email, password_hash, is_approved, role
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 0, 'user')
        """, (name, designation, department, supervisor_name, supervisor_email,
              company, location, email, hashed_password))
        mysql.connection.commit()

        # --- Notify Admins about new registration ---
        cur.execute("SELECT email FROM users WHERE role = 'admin' AND is_approved = 1")
        admins = cur.fetchall()
        if admins:
            admin_subject = "LFMS: New User Registration - LFMS Approval Required"
            approval_link = url_for('admin_approve', _external=True)
            admin_body = f"""
Hello Admin,

A new user has registered for the Legal File Management System (LFMS) and is awaiting your approval.

User Details:
- Name: {name}
- Email: {email}

Please visit the admin approval page to review and process this registration:
{approval_link}

Regards,
The LFMS System Bot
"""
            for admin in admins:
                send_email_async(app, admin['email'], admin_subject, admin_body)

        # Send email with password
        subject = "LFMS: Welcome to LFMS - Your Account Details"
        body = f"""
Hello {name},

Thank you for registering with the Legal File Management System (LFMS).
Your account has been created and is pending admin approval.

Once approved, you can log in with your email and the following temporary password:
Password: {password}

Please change your password after your first login for security.

Regards,
The LFMS Team
"""
        send_email_async(app, email, subject, body)
        flash('Thanks for registering. After admin approval, you can log in. Your temporary password has been sent to your email.', 'success')
        cur.close()
        return redirect(url_for('login'))

    cur.close()
    return render_template('register.html', supervisors=supervisors)

@app.route('/admin_approve')
@admin_required
def admin_approve():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM users WHERE is_approved=0")
    users = cur.fetchall()
    cur.close()
    return render_template('admin_approve.html', users=users)



@app.route('/approve_user', methods=['POST'])
def approve_user():
    user_id = request.form.get('user_id')
    selected_role = request.form.get('role')
    view_access = request.form.get('view_access')  # Get view access from form

    if user_id and selected_role and view_access:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        # Fetch user details before approving
        cur.execute("SELECT name, email FROM users WHERE user_id = %s", (user_id,))
        user = cur.fetchone()

        if not user:
            flash("User not found.", "danger")
            cur.close()
            return redirect(url_for('admin_approve'))

        cur.execute("""
            UPDATE users 
            SET is_approved = 1, role = %s, view_access = %s 
            WHERE user_id = %s
        """, (selected_role, view_access, user_id))
        mysql.connection.commit()
        cur.close()

        # Send approval email
        subject = "Your LFMS Account has been Approved"
        body = f"""
Hello {user['name']},

Congratulations! Your account for the Legal File Management System (LFMS) has been approved by the admin.

You can now log in to your account using your email and the temporary password that was sent to you upon registration.

Login here: {url_for('login', _external=True)}

Regards,
The LFMS Team
"""
        send_email_async(app, user['email'], subject, body)
        flash("User approved and a notification email has been sent.", "success")
    else:
        flash("Missing user ID, role, or view access selection.", "danger")

    return redirect(url_for('admin_approve'))

@app.route("/login/microsoft")
def microsoft_login():
    """Redirects to Microsoft's identity platform for authentication."""
    session["state"] = secrets.token_urlsafe(16)
    msal_app = msal.ConfidentialClientApplication(
        client_id=app.config['CLIENT_ID'],
        authority=app.config['AUTHORITY'],
        client_credential=app.config['CLIENT_SECRET'],
    )
    auth_url = msal_app.get_authorization_request_url(
        scopes=app.config['SCOPE'],
        state=session["state"],
        redirect_uri=url_for('get_token', _external=True)
    )
    return redirect(auth_url)

@app.route(app.config['REDIRECT_PATH'])
def get_token():
    """Callback route from Microsoft. Handles the token acquisition and user login."""
    if request.args.get('state') != session.get('state'):
        return redirect(url_for('login'))  # State does not match, abort.

    if "error" in request.args:
        flash(f"Error during SSO login: {request.args.get('error_description', 'Unknown error')}", "danger")
        return redirect(url_for("login"))

    if request.args.get('code'):
        msal_app = msal.ConfidentialClientApplication(
            client_id=app.config['CLIENT_ID'],
            authority=app.config['AUTHORITY'],
            client_credential=app.config['CLIENT_SECRET'],
        )
        result = msal_app.acquire_token_by_authorization_code(
            request.args['code'],
            scopes=app.config['SCOPE'],
            redirect_uri=url_for('get_token', _external=True)
        )

        if "error" in result:
            flash(f"Token acquisition failed: {result.get('error_description', 'Unknown error')}", "danger")
            return redirect(url_for("login"))

        # Get user info from Microsoft Graph
        graph_data = requests.get(
            app.config['ENDPOINT'],
            headers={'Authorization': 'Bearer ' + result['access_token']},
        ).json()

        sso_email = graph_data.get('userPrincipalName') or graph_data.get('mail')
        if not sso_email:
            flash("Could not retrieve email from Microsoft account.", "danger")
            return redirect(url_for("login"))

        # --- Log in the user based on the SSO email ---
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT * FROM users WHERE email = %s", (sso_email,))
        user = cur.fetchone()
        cur.close()

        if user:
            if user['is_approved'] == 0:
                flash('Your account is not approved by the admin yet.', 'warning')
                return redirect(url_for('login'))
            elif user['is_approved'] == 2:
                flash('Your registration has been rejected. Please contact an administrator.', 'danger')
                return redirect(url_for('login'))

            # User is valid and approved, log them in
            session['user_id'] = user['user_id']
            session['role'] = user['role']
            session['user_name'] = user['name']
            session['view_access'] = user.get('view_access', 'No') # Add view_access to session
            flash('Logged in successfully via Microsoft SSO.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('No account found with this Microsoft email. Please register first.', 'danger')
            return redirect(url_for('login'))

    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form['password']

        # --- SSO Domain Check ---
        # If the email domain is in our SSO list, redirect to Microsoft login.
        try:
            domain = email.split('@')[1]
            if domain in app.config.get('SSO_DOMAINS', []):
                return redirect(url_for('microsoft_login'))
        except IndexError:
            # Invalid email format, let the normal password check handle it.
            pass
        # --- End SSO Domain Check ---

        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT user_id, password_hash, is_approved, role, name, view_access
            FROM users 
            WHERE email = %s
        """, (email,))
        user = cur.fetchone()
        cur.close()

        if user:
            user_id, password_hash_db, is_approved, role, name, view_access = user

            if is_approved == 0:
                flash('Your account is not approved by the admin yet.', 'warning')
            elif is_approved == 2:
                flash('Your registration has been rejected. Please contact an administrator.', 'danger')
            elif password_hash_db and check_password_hash(password_hash_db, password):
                session['user_id'] = user_id
                session['role'] = role
                session['user_name'] = name
                session['view_access'] = view_access # Add view_access to session
                flash('Logged in successfully.', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Incorrect password.', 'danger')
        else:
            flash('No account found with this email.', 'danger')

    return render_template('login.html')
    
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required()
def dashboard():
    user_id = session['user_id']
    role = session['role']

    cur = mysql.connection.cursor() # Using tuple cursor for requests as per template

    if role == 'user':
        cur.execute("SELECT * FROM requests WHERE user_id=%s ORDER BY created_at DESC", (user_id,))
    elif role == 'supervisor':
        cur.execute("""
            SELECT r.* FROM requests r
            JOIN users u ON r.user_id = u.user_id
            WHERE u.supervisor_email = (SELECT email FROM users WHERE user_id=%s)
            AND r.status = 'supervisor_approval_pending'
            ORDER BY r.created_at DESC
        """, (user_id,))
    elif role == 'ceo':
        # CEO sees requests waiting for CEO approval
        cur.execute("""
            SELECT * FROM requests WHERE status = 'ceo_approval_pending'
            ORDER BY created_at DESC
        """)
    elif role == 'legal_team':
        cur.execute("""
            SELECT * FROM requests WHERE status IN ('supervisor_approved','ceo_approved','legal_feedback_given')
            ORDER BY created_at DESC
        """)
    elif role == 'admin':
        cur.execute("SELECT * FROM requests ORDER BY created_at DESC")
    else:
        cur.execute("SELECT * FROM requests ORDER BY created_at DESC")

    requests_data = cur.fetchall()
    cur.close()

    # For admins, also fetch users pending approval
    pending_users = []
    if role == 'admin':
        admin_cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor) # DictCursor for users
        admin_cur.execute("SELECT * FROM users WHERE is_approved=0")
        pending_users = admin_cur.fetchall()
        admin_cur.close()

    return render_template('dashboard.html', requests=requests_data, role=role, pending_users=pending_users)

@app.route('/request/new', methods=['GET', 'POST'])
@login_required(role='user')
def new_request():
    if request.method == 'POST':
        user_id = session['user_id']
        user_name = session['user_name']

        # Fetch form fields
        title = request.form.get('request_title')
        doc_type = request.form.get('document_type')
        doc_value = request.form.get('document_value')
        description = request.form.get('description')

        type_of_agreement = request.form.get('type_of_the_agreement')
        name_of_other_parties = request.form.get('name_of_the_other_parties')
        party_tpdd_status = request.form.get('Partys_tpdd_status')
        scope_of_work = request.form.get('scope_of_work')
        work_schedule = request.form.get('work_schedule_if_any')
        performed_by = request.form.get('performed_by')
        tenure_value = request.form.get('tenure_value')
        
        # New currency field
        currency = request.form.get('currency')
        
        effective_date = request.form.get('effective_date')
        amount_to_be_paid = request.form.get('amount_to_be_paid')
        ait = request.form.get('ait')
        vat = request.form.get('vat')
        other_costs = request.form.get('other_costs')
        payment_frequency = request.form.get('payment_frequency')
        advance_payment = request.form.get('advance_payment')
        security_deposit = request.form.get('security_deposit')
        security_cheque = request.form.get('security_cheque_or_bank_guarantee')
        penalty_matrix = request.form.get('penalty_deduction_matrix_for_default')
        termination_notice = request.form.get('termination_notice_period')
        termination_consequences = request.form.get('consequences_of_termination')
        assets_to_be_returned = request.form.get('assets_to_be_returned')
        name_of_notice_receivers = request.form.get('name_of_the_notice_receivers')
        designations_of_receivers = request.form.get('designations_of_receivers')
        # New fields for notice receivers
        notice_receiver_mobile_no = request.form.get('notice_receiver_mobile_no')  # Added field
        notice_receiver_email = request.form.get('notice_receiver_email')      # Added field
        notice_receiver_address = request.form.get('notice_receiver_address')  # Added field
        exclusivity = request.form.get('exclusivity')
        goal_sheet = request.form.get('goal_sheet')
        special_clause = request.form.get('any_other_special_clause')

        # Convert values to float for calculation
        def to_float(value):
            try:
                return float(value)
            except (TypeError, ValueError):
                return 0.0

        amount_to_be_paid_val = to_float(amount_to_be_paid)
        ait_val = to_float(ait)
        vat_val = to_float(vat)
        total_amount = amount_to_be_paid_val + ait_val + vat_val

        # Handle all attachments individually
        details_file = request.files.get('details_attachment')
        security_cheque_file = request.files.get('security_cheque_attachment')
        supporting_files = request.files.getlist('supporting_documents')

        # Consolidate all files for a single size check
        all_files_for_size_check = []
        if details_file and details_file.filename:
            all_files_for_size_check.append(details_file)
        if security_cheque_file and security_cheque_file.filename:
            all_files_for_size_check.append(security_cheque_file)
        all_files_for_size_check.extend([f for f in supporting_files if f and f.filename])

        if not is_total_upload_size_allowed(all_files_for_size_check, MAX_TOTAL_ATTACHMENT_SIZE):
            flash('Total attachment size must not exceed 2MB.', 'danger')
            return redirect(url_for('new_request'))

        # Insert into requests table
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO requests (
                user_id, user_name, request_title, document_type, document_value, description,
                type_of_the_agreement, name_of_the_other_parties, Partys_tpdd_status,
                scope_of_work, work_schedule_if_any, performed_by, tenure_value, currency, effective_date,
                amount_to_be_paid, ait, vat, other_costs, total_amount_including_vat_and_tax,
                payment_frequency, advance_payment, security_deposit, security_cheque_or_bank_guarantee,
                penalty_deduction_matrix_for_default, termination_notice_period, consequences_of_termination,
                assets_to_be_returned, name_of_the_notice_receivers, designations_of_receivers,
                notice_receiver_mobile_no, notice_receiver_email, notice_receiver_address,  -- Added columns
                exclusivity, goal_sheet, any_other_special_clause,
                status
            )
            VALUES (
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s,  -- Added values
                %s, %s, %s,
                'supervisor_approval_pending'
            )
        """, (
            user_id, user_name, title, doc_type, doc_value, description,
            type_of_agreement, name_of_other_parties, party_tpdd_status,
            scope_of_work, work_schedule, performed_by, tenure_value, currency, effective_date,
            amount_to_be_paid, ait, vat, other_costs, total_amount,
            payment_frequency, advance_payment, security_deposit, security_cheque,
            penalty_matrix, termination_notice, termination_consequences,
            assets_to_be_returned, name_of_notice_receivers, designations_of_receivers,
            notice_receiver_mobile_no, notice_receiver_email, notice_receiver_address,  # Added variables
            exclusivity, goal_sheet, special_clause
        ))
        mysql.connection.commit()

        # Get inserted request ID
        cur.execute("SELECT LAST_INSERT_ID()")
        request_id = cur.fetchone()[0]

        # Helper function to save files with a specific type
        def save_attachment(file, attachment_type):
            if file and allowed_file(file.filename):
                # Prepend timestamp to filename to avoid collisions
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                original_filename = secure_filename(file.filename)
                filename = f"{timestamp}_{original_filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                cur.execute("""
                    INSERT INTO attachments (request_id, uploaded_by, file_path, attachment_type)
                    VALUES (%s, %s, %s, %s)
                """, (request_id, user_id, filepath, attachment_type))
                mysql.connection.commit()

        save_attachment(details_file, 'initial_request')
        save_attachment(security_cheque_file, 'security_cheque')
        for file in supporting_files:
            save_attachment(file, 'supporting_document')

        # Log request activity
        action_details = "Request submitted by user."
        cur.execute("""
            INSERT INTO request_activity_log (request_id, action_type, performed_by, action_details)
            VALUES (%s, 'request_created', %s, %s)
        """, (request_id, user_id, action_details))
        mysql.connection.commit()

        # --- Send Email Notifications ---
        # Use a DictCursor to fetch user and supervisor emails
        email_cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        email_cur.execute("SELECT email, supervisor_email FROM users WHERE user_id = %s", (user_id,))
        user_info = email_cur.fetchone()
        email_cur.close()

        if user_info:
            user_email = user_info['email']
            supervisor_email = user_info['supervisor_email']
            request_url = url_for('view_request', request_id=request_id, _external=True)

            # 1. Email to the user who made the request
            user_subject = f"LFMS: Confirmation: Your LFMS Request (REQ-{request_id}) is Submitted"
            user_body = f"""
Hello {user_name},

This is a confirmation that your request titled "{title}" has been successfully submitted and sent to your supervisor for approval.

You can view the status of your request here:
{request_url}

Regards,
The LFMS Team
"""
            send_email_async(app, user_email, user_subject, user_body)

            # 2. Email to the supervisor
            if supervisor_email:
                supervisor_subject = f"LFMS: Action Required: New LFMS Request from {user_name} (REQ-{request_id})"
                supervisor_body = f"""
Hello,

A new legal request titled "{title}" from {user_name} requires your approval.

Please review the request details and take action by clicking the link below:
{request_url}

Regards,
The LFMS System
"""
                send_email_async(app, supervisor_email, supervisor_subject, supervisor_body)
        cur.close()

        flash('Your request has been sent for approval. You and your supervisor have been notified by email.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('new_request.html')

@app.route('/request/<int:request_id>')
@login_required()
def view_request(request_id):
    user_id = session['user_id']
    role = session['role']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Fetch request info with all fields same as in new_request, including new fields
    cur.execute("""
        SELECT 
            r.request_id,
            r.user_id,
            u.name AS user_name,
            r.request_title,
            r.document_type,
            r.document_value,
            r.description,
            r.type_of_the_agreement,
            r.name_of_the_other_parties,
            r.Partys_tpdd_status,
            r.scope_of_work,
            r.work_schedule_if_any,
            r.performed_by,
            r.tenure_value,
            r.currency,
            r.effective_date,
            r.amount_to_be_paid,
            r.ait,
            r.vat,
            r.other_costs,
            r.total_amount_including_vat_and_tax,
            r.payment_frequency,
            r.advance_payment,
            r.security_deposit,
            r.security_cheque_or_bank_guarantee,
            r.penalty_deduction_matrix_for_default,
            r.termination_notice_period,
            r.consequences_of_termination,
            r.assets_to_be_returned,
            r.name_of_the_notice_receivers,
            r.designations_of_receivers,
            r.notice_receiver_mobile_no,  -- Added field
            r.notice_receiver_email,      -- Added field
            r.notice_receiver_address,  -- Added field
            r.exclusivity,
            r.goal_sheet,
            r.any_other_special_clause,
            r.status,
            r.created_at,
            r.approved_by_supervisor,
            r.supervisor_approval_date,
            r.approved_by_ceo,
            r.ceo_approval_date,
            r.legal_feedback_by,
            r.final_submitted_by,
            r.final_submitted_at,
            r.rejected_by
        FROM requests r
        JOIN users u ON r.user_id = u.user_id
        WHERE r.request_id = %s
    """, (request_id,))
    req = cur.fetchone()

    if not req:
        flash('Request not found or you do not have permission.', 'danger')
        return redirect(url_for('dashboard'))

    # Role-based access check
    allowed_roles = ['supervisor', 'ceo', 'legal_team', 'admin']
    if role == 'user' and req['user_id'] != user_id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    elif role not in allowed_roles and role != 'user':
        flash('Unauthorized role', 'danger')
        return redirect(url_for('dashboard'))

    # Fetch attachments
    cur.execute("""
        SELECT attachment_id, file_path, attachment_type, uploaded_by, uploaded_at
        FROM attachments
        WHERE request_id = %s
    """, (request_id,))
    attachments = cur.fetchall()

    # Fetch feedbacks
    try:
        cur.execute("""
            SELECT feedback_id, feedback_type, provided_by, comment, submitted_at
            FROM feedbacks
            WHERE request_id = %s
            ORDER BY submitted_at
        """, (request_id,))
        feedbacks = cur.fetchall()
    except MySQLdb.OperationalError:
        feedbacks = [] # If feedbacks table doesn't exist, treat as no feedback

    # Fetch final document
    cur.execute("""
        SELECT final_doc_id, validity_start, validity_end, final_file_path
        FROM final_documents
        WHERE request_id = %s
    """, (request_id,))
    final_doc = cur.fetchone()

    cur.close()

    return render_template(
        'view_request.html',
        request=req,
        attachments=attachments,
        feedbacks=feedbacks,
        final_doc=final_doc,
        role=role
    )


@app.route('/approve/<int:request_id>', methods=['POST'])
@login_required(role='supervisor')
def supervisor_approve(request_id):
    approval_note = request.form.get('approval_note')
    cur = mysql.connection.cursor()
    cur.execute("SELECT document_value FROM requests WHERE request_id = %s", (request_id,))
    result = cur.fetchone()

    if not result:
        flash("Request not found.", "danger")
        return redirect(url_for('dashboard'))

    value = result[0]
    if value <= 50000:
        status = 'supervisor_approved'
    else:
        status = 'ceo_approval_pending'

    cur.execute("""
        UPDATE requests 
        SET status = %s, approved_by_supervisor = %s, supervisor_approval_date = %s, approval_note = %s
        WHERE request_id = %s
    """, (status, session['user_name'], datetime.now(), approval_note, request_id))

    # Also insert into request_activity_log for audit trail
    action_details = f"Supervisor approved request. Status set to {status}. Note: {approval_note}"
    cur.execute("""
        INSERT INTO request_activity_log (request_id, action_type, performed_by, action_details)
        VALUES (%s, 'supervisor_approved', %s, %s)
    """, (request_id, session['user_id'], action_details))

    mysql.connection.commit()

    # --- Send Email Notification to Requester ---
    email_cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    email_cur.execute("""
        SELECT u.email, u.name, r.request_title 
        FROM requests r 
        JOIN users u ON r.user_id = u.user_id 
        WHERE r.request_id = %s
    """, (request_id,))
    request_info = email_cur.fetchone()
    email_cur.close()

    if request_info:
        requester_email = request_info['email']
        requester_name = request_info['name']
        request_title = request_info['request_title']
        view_url = url_for('view_request', request_id=request_id, _external=True)
        
        subject = f"LFMS: Update on Your Request: REQ-{request_id} - Approved by Supervisor"
        
        if status == 'ceo_approval_pending':
            body = f"""
Hello {requester_name},

Your request "{request_title}" has been approved by your supervisor and has been forwarded to the CEO for final approval.

You can view the request status here:
{view_url}

Regards,
The LFMS System
"""
        else: # supervisor_approved
            body = f"""
Hello {requester_name},

Your request "{request_title}" has been approved by your supervisor and is now with the legal team for processing.

You can view the request status here:
{view_url}

Regards,
The LFMS System
"""
        send_email_async(app, requester_email, subject, body)
    # --- End Email Notification ---

    cur.close()

    flash("Request approved successfully.", "success")
    return redirect(url_for('dashboard'))


@app.route('/ceo_approve/<int:request_id>', methods=['POST'])
@login_required(role='ceo')
def ceo_approve(request_id):
    user_id = session['user_id']
    ceo_note = request.form.get('ceo_approval_note')  # Get note from form

    cur = mysql.connection.cursor()

    # Check status is 'ceo_approval_pending'
    cur.execute("SELECT status FROM requests WHERE request_id=%s", (request_id,))
    data = cur.fetchone()
    if not data or data[0] != 'ceo_approval_pending':
        flash('Invalid request status for CEO approval.', 'danger')
        return redirect(url_for('dashboard'))

    # Update status, CEO info and note
    cur.execute("""
        UPDATE requests 
        SET status = %s, 
            approved_by_ceo = %s, 
            ceo_approval_date = %s,
            ceo_approval_note = %s
        WHERE request_id = %s
    """, ('ceo_approved', session['user_name'], datetime.now(), ceo_note, request_id))

    # Log CEO approval activity
    action_details = f"CEO approved request. Note: {ceo_note}"
    cur.execute("""
        INSERT INTO request_activity_log (request_id, action_type, performed_by, action_details)
        VALUES (%s, 'ceo_approved', %s, %s)
    """, (request_id, user_id, action_details))

    mysql.connection.commit()

    # --- Send Email Notification to Requester ---
    email_cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    email_cur.execute("""
        SELECT u.email, u.name, r.request_title 
        FROM requests r 
        JOIN users u ON r.user_id = u.user_id 
        WHERE r.request_id = %s
    """, (request_id,))
    request_info = email_cur.fetchone()
    email_cur.close()

    if request_info:
        requester_email = request_info['email']
        requester_name = request_info['name']
        request_title = request_info['request_title']
        view_url = url_for('view_request', request_id=request_id, _external=True)
        
        subject = f"LFMS: Update on Your Request: REQ-{request_id} - Approved by CEO"
        body = f"""
Hello {requester_name},

Your request "{request_title}" has been approved by the CEO and is now with the legal team for processing.

You can view the request status here:
{view_url}

Regards,
The LFMS System
"""
        send_email_async(app, requester_email, subject, body)
    # --- End Email Notification ---

    cur.close()
    flash('Request approved by CEO.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/legal_feedback/<int:request_id>', methods=['GET', 'POST'])
@login_required(role='legal_team')
def legal_feedback(request_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT status FROM requests WHERE request_id=%s", (request_id,))
    status_result = cur.fetchone()
    if status_result and status_result[0] == 'final_documents_avaiable':
        flash('Final document already submitted. Feedback is no longer allowed.', 'warning')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        comment = request.form['comment']
        files = request.files.getlist('attachments')
        if not is_total_upload_size_allowed(files, MAX_TOTAL_ATTACHMENT_SIZE):
            flash('Total attachment size must not exceed 2MB.', 'danger')
            return redirect(url_for('legal_feedback', request_id=request_id))

        try:
            cur.execute("""
                INSERT INTO feedbacks (request_id, provided_by, comment, feedback_type)
                VALUES (%s, %s, %s, 'legal')
            """, (request_id, session['user_id'], comment))
        except MySQLdb.OperationalError as e:
            flash(f"Database error: {e}. Please ensure the 'feedbacks' table exists.", 'danger')
            cur.close()
            return redirect(url_for('view_request', request_id=request_id))

        feedback_id = cur.lastrowid

        # Save attachments for feedback
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                # Attach feedback attachments to attachments table
                cur.execute("""
                    INSERT INTO attachments (request_id, uploaded_by, file_path, attachment_type)
                    VALUES (%s, %s, %s, 'legal_feedback')
                """, (request_id, session['user_id'], filepath))

        # **Update the requests table with legal feedback info**
        cur.execute("""
            UPDATE requests
            SET legal_feedback = %s,
                legal_feedback_by = %s,
                legal_feedback_date = %s
            WHERE request_id = %s
        """, (comment, session['user_name'], datetime.now(), request_id))

        mysql.connection.commit()

        # Insert into request_activity_log: legal_feedback_added
        user_id = session['user_id']
        attachment_path = None
        if files and len(files) > 0 and allowed_file(files[0].filename):
            filename = secure_filename(files[0].filename)
            attachment_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        action_details = f"Legal feedback added: {comment}"
        cur.execute("""
            INSERT INTO request_activity_log (request_id, action_type, performed_by, action_details, attachment_path)
            VALUES (%s, 'legal_feedback_added', %s, %s, %s)
        """, (request_id, user_id, action_details, attachment_path))
        mysql.connection.commit()

        # --- Send Email Notification to Requester ---
        email_cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        email_cur.execute("""
            SELECT u.email, u.name, r.request_title 
            FROM requests r 
            JOIN users u ON r.user_id = u.user_id 
            WHERE r.request_id = %s
        """, (request_id,))
        request_info = email_cur.fetchone()
        email_cur.close()

        if request_info:
            requester_email = request_info['email']
            requester_name = request_info['name']
            request_title = request_info['request_title']
            view_url = url_for('view_request', request_id=request_id, _external=True)
            
            subject = f"LFMS: Feedback Received for Your Request: REQ-{request_id}"
            body = f"""
Hello {requester_name},

The legal team has provided feedback on your request "{request_title}".

Feedback:
"{comment}"

Please review the feedback and take necessary action by clicking the link below:
{view_url}

Regards,
The LFMS System
"""
            send_email_async(app, requester_email, subject, body)
        # --- End Email Notification ---

        flash('Legal feedback submitted.', 'success')
        return redirect(url_for('dashboard'))

    # GET request show form
    cur.execute("SELECT * FROM requests WHERE request_id=%s", (request_id,))
    req = cur.fetchone()
    cur.close()
    if not req:
        flash('Request not found.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('legal_feedback.html', request=req)


@app.route('/user_feedback/<int:request_id>', methods=['GET', 'POST'])
@login_required(role='user')
def user_feedback(request_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT status FROM requests WHERE request_id=%s", (request_id,))
    status_result = cur.fetchone()
    if status_result and status_result[0] == 'final_documents_avaiable':
        flash('Final document already submitted. Feedback is no longer allowed.', 'warning')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user_feedback = request.form['comment']  # renamed for clarity
        files = request.files.getlist('attachments')
        if not is_total_upload_size_allowed(files, MAX_TOTAL_ATTACHMENT_SIZE):
            flash('Total attachment size must not exceed 2MB.', 'danger')
            return redirect(url_for('user_feedback', request_id=request_id))


        try:
            cur.execute("""
                INSERT INTO feedbacks (request_id, provided_by, comment, feedback_type)
                VALUES (%s, %s, %s, 'user')
            """, (request_id, session['user_id'], user_feedback))
        except MySQLdb.OperationalError as e:
            flash(f"Database error: {e}. Please ensure the 'feedbacks' table exists.", 'danger')
            cur.close()
            return redirect(url_for('view_request', request_id=request_id))

        feedback_id = cur.lastrowid

        # Update the requests table with user feedback and date
        cur.execute("""
            UPDATE requests
            SET user_feedback = %s,
                user_feedback_date = %s
            WHERE request_id = %s
        """, (user_feedback, datetime.now(), request_id))

        # Handle file attachments
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                cur.execute("""
                    INSERT INTO attachments (request_id, uploaded_by, file_path, attachment_type)
                    VALUES (%s, %s, %s, 'user_feedback')
                """, (request_id, session['user_id'], filepath))

        mysql.connection.commit()

        # Insert into request_activity_log: user_feedback_added
        user_id = session['user_id']
        attachment_path = None
        if files and len(files) > 0 and allowed_file(files[0].filename):
            filename = secure_filename(files[0].filename)
            attachment_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        action_details = f"User feedback added: {user_feedback}"
        cur.execute("""
            INSERT INTO request_activity_log (request_id, action_type, performed_by, action_details, attachment_path)
            VALUES (%s, 'user_feedback_added', %s, %s, %s)
        """, (request_id, user_id, action_details, attachment_path))
        mysql.connection.commit()

        # --- Send Email Notification to Legal Team ---
        email_cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        # Get legal team emails
        email_cur.execute("SELECT email FROM users WHERE role = 'legal_team' AND is_approved = 1")
        legal_team_users = email_cur.fetchall()
        legal_team_emails = [user['email'] for user in legal_team_users]

        # Get request info
        email_cur.execute("SELECT request_title FROM requests WHERE request_id = %s", (request_id,))
        request_info = email_cur.fetchone()
        email_cur.close()

        if legal_team_emails and request_info:
            request_title = request_info['request_title']
            user_name = session.get('user_name', 'A user')
            view_url = url_for('view_request', request_id=request_id, _external=True)

            subject = f"LFMS: User Feedback Submitted for Request: REQ-{request_id}"
            body = f"""
Hello Legal Team,

A user has submitted feedback regarding the request titled "{request_title}".

Submitted by: {user_name}
Feedback:
"{user_feedback}"

Please review the request and the new feedback by clicking the link below:
{view_url}

Regards,
The LFMS System
"""
            for email in legal_team_emails:
                send_email_async(app, email, subject, body)

        flash('Your feedback has been submitted.', 'success')
        return redirect(url_for('view_request', request_id=request_id))

    # GET method
    cur.execute("SELECT * FROM requests WHERE request_id=%s", (request_id,))
    req = cur.fetchone()
    cur.close()
    if not req:
        flash('Request not found.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('user_feedback.html', request=req)


@app.route('/final_upload/<int:request_id>', methods=['GET', 'POST'])
@login_required(role='legal_team')
def final_upload(request_id):
    cur = mysql.connection.cursor()

    # Check if a final document already exists
    cur.execute("SELECT status FROM requests WHERE request_id = %s", (request_id,))
    req_status = cur.fetchone()
    if req_status and req_status[0] == 'final_documents_avaiable':
        flash('A final document has already been uploaded for this request.', 'warning')
        cur.close()
        return redirect(url_for('view_request', request_id=request_id))

    if request.method == 'POST':
        validity_start = request.form['validity_start']
        validity_end = request.form['validity_end']

        if not request.form.get('confirmation1') or not request.form.get('confirmation2'):
            flash('You must confirm both checkboxes before submitting.', 'danger')
            cur.close()
            return redirect(url_for('final_upload', request_id=request_id))

        file = request.files.get('final_file')
        if not file or file.filename == '':
            flash('No file selected.', 'danger')
            cur.close()
            return redirect(url_for('final_upload', request_id=request_id))

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            cur.execute("""
                UPDATE requests
                SET final_file_path = %s,
                    final_submitted_by = %s,
                    final_submitted_at = %s,
                    status = 'final_documents_avaiable'
                WHERE request_id = %s
            """, (filepath, session['user_name'], datetime.now(), request_id))

            cur.execute("""
                INSERT INTO final_documents (request_id, legal_team_id, validity_start, validity_end, final_file_path)
                VALUES (%s, %s, %s, %s, %s)
            """, (request_id, session['user_id'], validity_start, validity_end, filepath))

            mysql.connection.commit()

            user_id = session['user_id']
            action_details = f"Final document uploaded. Validity: {validity_start} to {validity_end}"
            cur.execute("""
                INSERT INTO request_activity_log (request_id, action_type, performed_by, action_details, attachment_path)
                VALUES (%s, 'final_document_uploaded', %s, %s, %s)
            """, (request_id, user_id, action_details, filepath))
            mysql.connection.commit()

            # --- Send Email Notification to Requester ---
            email_cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            # Get requester's email and name, and the request title
            email_cur.execute("""
                SELECT u.email, u.name, r.request_title
                FROM requests r
                JOIN users u ON r.user_id = u.user_id
                WHERE r.request_id = %s
            """, (request_id,))
            request_info = email_cur.fetchone()
            email_cur.close()

            if request_info:
                requester_email = request_info['email']
                requester_name = request_info['name']
                request_title = request_info['request_title']
                view_url = url_for('view_request', request_id=request_id, _external=True)
                
                subject = f"LFMS: Final Document Available for Your Request: REQ-{request_id}"
                body = f"""
Hello {requester_name},

The final document for your request "{request_title}" has been uploaded by the legal team.

You can view the request details and download the final document by clicking the link below:
{view_url}

Regards,
The LFMS System
"""
                send_email_async(app, requester_email, subject, body)
                flash('Final document uploaded and the requester has been notified.', 'success')
            else:
                flash('Final document uploaded.', 'success')

            cur.close()
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid file.', 'danger')
            cur.close()
            return redirect(url_for('final_upload', request_id=request_id))

    cur.execute("SELECT * FROM requests WHERE request_id=%s", (request_id,))
    req = cur.fetchone()
    cur.close()
    if not req:
        flash('Request not found.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('final_upload.html', request=req)


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/download/<path:filename>')
def download_file(filename):
    uploads_dir = app.config['UPLOAD_FOLDER']  # Use the same as uploads
    filepath = safe_join(uploads_dir, filename)  

    if not filepath or not os.path.isfile(filepath):
        print(f"File not found: {filepath}")
        abort(404)

    return send_file(filepath, as_attachment=True)


@app.route('/reject_request/<int:request_id>', methods=['POST'])
@login_required()
def reject_request(request_id):
    role = session.get('role')
    user_id = session.get('user_id')  # Using user_id to store rejected_by

    reason = request.form.get('reason')

    # Define which roles can reject and at what statuses
    role_allowed_statuses = {
        'supervisor': ['supervisor_approval_pending', 'supervisor_approved'],  # adjust as needed
        'ceo': ['ceo_approval_pending', 'ceo_approved'],  # adjust as needed
        'legal_team': ['supervisor_approved', 'ceo_approved', 'legal_feedback_given', 'final_documents_avaiable']
    }

    # Check if role can reject at all
    if role not in role_allowed_statuses:
        flash('You do not have permission to reject.', 'danger')
        return redirect(url_for('dashboard'))

    cur = mysql.connection.cursor()

    # Get current request status
    cur.execute("SELECT status FROM requests WHERE request_id = %s", (request_id,))
    result = cur.fetchone()

    if not result:
        flash('Request not found.', 'danger')
        return redirect(url_for('dashboard'))

    status = result[0]

    # Check if current status allows rejection by this role
    allowed_statuses = role_allowed_statuses[role]
    if status not in allowed_statuses:
        flash(f'You cannot reject this request in its current status: {status}', 'warning')
        return redirect(url_for('dashboard'))

    # Perform rejection
    rejected_at = datetime.now()
    cur.execute("""
        UPDATE requests
        SET status = %s,
            rejected_reason = %s,
            rejected_by = %s,
            rejected_at = %s
        WHERE request_id = %s
    """, ('rejected', reason, user_id, rejected_at, request_id))

    # Log activity
    action_details = f"Request rejected by {role}. Reason: {reason}"
    cur.execute("""
        INSERT INTO request_activity_log (request_id, action_type, performed_by, action_details)
        VALUES (%s, 'rejected', %s, %s)
    """, (request_id, user_id, action_details))

    mysql.connection.commit()

    # --- Send Email Notification to Requester ---
    email_cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    email_cur.execute("""
        SELECT u.email, u.name, r.request_title 
        FROM requests r 
        JOIN users u ON r.user_id = u.user_id 
        WHERE r.request_id = %s
    """, (request_id,))
    request_info = email_cur.fetchone()
    email_cur.close()

    if request_info:
        requester_email = request_info['email']
        requester_name = request_info['name']
        request_title = request_info['request_title']
        view_url = url_for('view_request', request_id=request_id, _external=True)
        
        subject = f"LFMS: Action Required: Your Request REQ-{request_id} has been Rejected"
        body = f"""
Hello {requester_name},

We are writing to inform you that your request "{request_title}" has been rejected.

Rejected by: {role.replace('_', ' ').title()}
Reason: {reason}

You can view the request details here:
{view_url}

If you have any questions, please contact the relevant department.

Regards,
The LFMS System
"""
        send_email_async(app, requester_email, subject, body)
    # --- End Email Notification ---

    cur.close()

    flash(f'Request rejected successfully by {role}.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/reject_user/<int:user_id>')
def reject_user(user_id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Fetch user details before deleting
    cur.execute("SELECT name, email FROM users WHERE user_id = %s", (user_id,))
    user = cur.fetchone()

    if user:
        # Update the user's status to rejected (2)
        cur.execute("UPDATE users SET is_approved = 2 WHERE user_id = %s", (user_id,))
        mysql.connection.commit()

        # Send rejection email
        subject = "LFMS: Update on Your LFMS Registration"
        body = f"""
Hello {user['name']},

We are writing to inform you about the status of your registration for the Legal File Management System (LFMS).

After a review, your registration request has been rejected. If you believe this is an error, please contact the system administrator.

Thank you for your understanding.

Regards,
The LFMS Team
"""
        send_email_async(app, user['email'], subject, body)
        flash("User rejected and a notification email has been sent.", "success")
    else:
        flash("User not found.", "danger")

    cur.close()
    return redirect(url_for('admin_approve'))

from datetime import date

@app.route('/all_legal_documents')
@login_required()
def all_legal_documents():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Check if user has view_access
    cur.execute("SELECT view_access FROM users WHERE user_id = %s", (session['user_id'],))
    access = cur.fetchone()
    
    if not access or access['view_access'] != 'Yes':
        cur.close()
        flash('Sorry, you have no permission to view legal documents.', 'danger')
        return redirect(url_for('dashboard'))

    cur.execute("""
        SELECT r.*, 
               u.name AS user_name,
               r.final_submitted_by,
               fd.final_file_path AS final_document,
               fd.validity_start, 
               fd.validity_end
        FROM requests r
        JOIN users u ON r.user_id = u.user_id
        LEFT JOIN final_documents fd ON r.request_id = fd.request_id
        WHERE r.status = 'final_documents_avaiable'
    """)
    legal_docs = cur.fetchall()
    cur.close()

    # Sort documents: active first, then expired
    today = date.today()
    active_docs = []
    expired_docs = []

    for doc in legal_docs:
        # The value from DB is already a date object or None
        if doc.get('validity_end') and doc['validity_end'] < today:
            expired_docs.append(doc)
        else:
            active_docs.append(doc)

    # Sort active documents by nearest expiry date first
    # Documents without an end date will be treated as having a far-future expiry
    active_docs.sort(key=lambda d: d.get('validity_end') or date.max)
    
    # Sort expired documents by most recently expired first
    expired_docs.sort(key=lambda d: d.get('validity_end') or date.min, reverse=True)

    sorted_docs = active_docs + expired_docs

    return render_template('all_legal_documents.html', documents=sorted_docs, current_date=today)

@app.route('/all_requests')
@login_required()
def all_requests():
    if session.get('role') != 'legal_team':
        flash("Access denied!", "danger")
        return redirect(url_for('dashboard'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Fetch all columns from requests table and join to get rejector's name
    cursor.execute("""
        SELECT 
            r.*,
            u_rej.name AS rejector_name
        FROM requests r
        LEFT JOIN users u_rej ON r.rejected_by = u_rej.user_id
        ORDER BY r.request_id DESC
    """)
    requests = cursor.fetchall()
    cursor.close()
    return render_template('all_requests.html', requests=requests)



@app.route('/my_approved_requests')
@login_required()
def my_approved_requests():
    user_name = session.get('user_name')
    role = session.get('role')

    if role not in ['supervisor', 'ceo']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if role == 'supervisor':
        cur.execute("""
            SELECT * FROM requests
            WHERE approved_by_supervisor = %s
            ORDER BY supervisor_approval_date DESC
        """, (user_name,))
    elif role == 'ceo':
        cur.execute("""
            SELECT * FROM requests
            WHERE approved_by_ceo = %s
            ORDER BY ceo_approval_date DESC
        """, (user_name,))

    approved_requests = cur.fetchall()
    cur.close()

    return render_template('my_approve_requests.html', requests=approved_requests, role=role)
# Admin check decorator
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/manage_users')
@login_required()
@admin_required
def manage_users():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM users ORDER BY created_at DESC")
    users = cur.fetchall()
    cur.close()
    return render_template('manage_user.html', users=users)


@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required()
@admin_required
def add_user():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Get supervisor list for dropdown
    cur.execute("SELECT name, email FROM users WHERE role IN ('supervisor', 'ceo', 'admin') AND is_approved = 1")
    supervisors = cur.fetchall()

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        role = request.form['role']
        view_access = request.form['view_access']
        is_approved = int(request.form.get('is_approved', 0))
        
        designation = request.form['designation']
        department = request.form['department']
        supervisor_name = request.form['supervisor_name']
        supervisor_email = request.form['supervisor_email']
        company = request.form['company']
        location = request.form['location']

        # Check if email already exists
        cur.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        if cur.fetchone():
            flash('Email already exists.', 'danger')
            return render_template('add_user.html', supervisors=supervisors)

        # Generate temporary password
        password = generate_password()
        hashed_password = generate_password_hash(password)

        # Insert new user
        cur.execute("""
            INSERT INTO users (name, email, role, view_access, is_approved, designation, department, supervisor_name, supervisor_email, company, location, password_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (name, email, role, view_access, is_approved, designation, department, supervisor_name, supervisor_email, company, location, hashed_password))
        mysql.connection.commit()

        # Send welcome email with password
        subject = "LFMS: Welcome to LFMS - Your Account is Ready"
        body = f"Hello {name},\n\nAn account has been created for you in the LFMS by an administrator.\n\nYour temporary password is: {password}\n\nPlease change it after your first login."
        send_email_async(app, email, subject, body)

        flash('User added successfully. A welcome email with a temporary password has been sent.', 'success')
        cur.close()
        return redirect(url_for('manage_users'))

    cur.close()
    return render_template('add_user.html', supervisors=supervisors)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required()
@admin_required
def edit_user(user_id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        # Gather form data
        name = request.form['name']
        email = request.form['email']
        role = request.form['role']
        view_access = request.form['view_access']
        is_approved = int(request.form.get('is_approved', 0))  # convert to int
        
        designation = request.form['designation']
        department = request.form['department']
        supervisor_name = request.form['supervisor_name']
        supervisor_email = request.form['supervisor_email']
        company = request.form['company']
        location = request.form['location']

        # Update user in DB
        cur.execute("""
            UPDATE users
            SET name=%s, email=%s, role=%s, view_access=%s, is_approved=%s,
                 designation=%s, department=%s, supervisor_name=%s, supervisor_email=%s, 
                 company=%s, location=%s
            WHERE user_id=%s
        """, (name, email, role, view_access, is_approved, designation, department, supervisor_name, supervisor_email, company, location, user_id))
        mysql.connection.commit()
        cur.close()

        flash('User updated successfully!', 'success')
        return redirect(url_for('manage_users'))

    # GET request: fetch user data
    cur.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()

    if not user:
        abort(404)

    return render_template('edit_user.html', user=user)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required()
@admin_required
def delete_user(user_id):
    """
    Deletes a user only if they have no associated records in other tables.
    This prevents orphaned records and maintains data integrity.
    """
    cur = mysql.connection.cursor()

    # Define checks for related records to ensure data integrity
    checks = {
        "requests created": "SELECT COUNT(*) FROM requests WHERE user_id = %s",
        "attachments uploaded": "SELECT COUNT(*) FROM attachments WHERE uploaded_by = %s",
        "feedback provided": "SELECT COUNT(*) FROM feedbacks WHERE provided_by = %s",
        "final documents uploaded": "SELECT COUNT(*) FROM final_documents WHERE legal_team_id = %s",
        "activity log entries": "SELECT COUNT(*) FROM request_activity_log WHERE performed_by = %s",
        "requests rejected": "SELECT COUNT(*) FROM requests WHERE rejected_by = %s",
    }

    for item_name, query in checks.items():
        cur.execute(query, (user_id,))
        if cur.fetchone()[0] > 0:
            flash(f'Cannot delete user. This user has related {item_name}. Please lock the user instead.', 'danger')
            cur.close()
            return redirect(url_for('manage_users'))

    # If no related records, proceed with deletion
    cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('manage_users'))


@app.route('/lock_user/<int:user_id>', methods=['POST'])
@login_required()
@admin_required
def lock_user(user_id):
    cur = mysql.connection.cursor()
    # Set is_approved = 0 to lock the user
    cur.execute("UPDATE users SET is_approved = 0 WHERE user_id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()
    flash('User locked successfully!', 'warning')
    return redirect(url_for('edit_user', user_id=user_id))



import random
import string
from werkzeug.security import generate_password_hash

@app.route('/reset_password/<int:user_id>', methods=['POST'])
@login_required()
@admin_required
def reset_password(user_id):
    # Generate a secure password
    new_password = generate_password()

    # Hash the password
    hashed_password = generate_password_hash(new_password)

    # Update DB and get user info for email
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("UPDATE users SET password_hash = %s WHERE user_id = %s", (hashed_password, user_id))
    cur.execute("SELECT name, email FROM users WHERE user_id = %s", (user_id,))
    user = cur.fetchone()
    mysql.connection.commit()
    cur.close()

    if user:
        # Send email with the new password
        subject = "LFMS: Your LFMS Password Has Been Reset"
        body = f"""
Hello {user['name']},

Your password for the Legal File Management System (LFMS) has been reset by an administrator.

Your new temporary password is:
Password: {new_password}

Please log in and change your password as soon as possible for security.

Regards,
The LFMS Team
"""
        send_email_async(app, user['email'], subject, body)
        flash(f"Password for {user['name']} has been reset and sent to their email.", 'success')
    else:
        flash("Password was reset, but could not find user to send email.", "warning")

    return redirect(url_for('manage_users'))


@app.route('/unlock_user/<int:user_id>', methods=['POST'])
@login_required()
@admin_required
def unlock_user(user_id):
    cur = mysql.connection.cursor()
    # Set is_approved = 1 to unlock the user
    cur.execute("UPDATE users SET is_approved = 1 WHERE user_id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()
    flash('User unlocked successfully!', 'success')
    return redirect(url_for('edit_user', user_id=user_id))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()

        if user:
            # Generate token
            token = serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])
            
            # Create reset link
            reset_url = url_for('reset_with_token', token=token, _external=True)
            
            subject = "LFMS: Password Reset Request for LFMS"
            body = f"""
Hello {user['name']},

You requested a password reset for your LFMS account.
Please click the link below to set a new password. This link will expire in 1 hour.

{reset_url}

If you did not request a password reset, please ignore this email.

Regards,
The LFMS Team"""
            send_email_async(app, email, subject, body)
        # To prevent user enumeration, show the same message whether the user exists or not.
        flash('A verification link has been sent to your mail.', 'success')
        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        # Token expires in 3600 seconds = 1 hour
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except Exception:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password_token.html')

        hashed_password = generate_password_hash(password)
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET password_hash = %s WHERE email = %s", (hashed_password, email))
        mysql.connection.commit()
        cur.close()

        flash('Your password has been updated successfully. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password_token.html')

@app.route('/request/new_nda', methods=['GET', 'POST'])
@login_required()  # Keep this login_required
def new_request_nda():
    if request.method == 'POST':
        user_id = session['user_id']
        user_name = session['user_name']

        # Fetch form fields
        title = request.form.get('request_title')
        doc_type = request.form.get('document_type')
        doc_value = request.form.get('document_value')
        description = request.form.get('description')

        type_of_agreement = request.form.get('type_of_the_agreement')
        name_of_other_parties = request.form.get('name_of_the_other_parties')
        party_tpdd_status = request.form.get('Partys_tpdd_status')
        scope_of_work = request.form.get('scope_of_work')
        work_schedule = request.form.get('work_schedule_if_any')
        performed_by = request.form.get('performed_by')
        tenure_value = request.form.get('tenure_value')
        
        # New currency field
        currency = request.form.get('currency')
        
        effective_date = request.form.get('effective_date')
        amount_to_be_paid = request.form.get('amount_to_be_paid')
        ait = request.form.get('ait')
        vat = request.form.get('vat')
        other_costs = request.form.get('other_costs')
        payment_frequency = request.form.get('payment_frequency')
        advance_payment = request.form.get('advance_payment')
        security_deposit = request.form.get('security_deposit')
        security_cheque = request.form.get('security_cheque_or_bank_guarantee')
        penalty_matrix = request.form.get('penalty_deduction_matrix_for_default')
        termination_notice = request.form.get('termination_notice_period')
        termination_consequences = request.form.get('consequences_of_termination')
        assets_to_be_returned = request.form.get('assets_to_be_returned')
        name_of_notice_receivers = request.form.get('name_of_the_notice_receivers')
        designations_of_receivers = request.form.get('designations_of_receivers')
        # New fields for notice receivers
        notice_receiver_mobile_no = request.form.get('notice_receiver_mobile_no')  # Added field
        notice_receiver_email = request.form.get('notice_receiver_email')      # Added field
        notice_receiver_address = request.form.get('notice_receiver_address')  # Added field
        exclusivity = request.form.get('exclusivity')
        goal_sheet = request.form.get('goal_sheet')
        special_clause = request.form.get('any_other_special_clause')

        # Convert values to float for calculation
        def to_float(value):
            try:
                return float(value)
            except (TypeError, ValueError):
                return 0.0

        amount_to_be_paid_val = to_float(amount_to_be_paid)
        ait_val = to_float(ait)
        vat_val = to_float(vat)
        total_amount = amount_to_be_paid_val + ait_val + vat_val

        # Handle attachments from both the required field and dynamic fields
        details_file = request.files.get('details_attachment')
        supporting_files = request.files.getlist('supporting_documents')

        all_files = []
        if details_file and details_file.filename:
            all_files.append(details_file)
        all_files.extend([f for f in supporting_files if f and f.filename])

        if not is_total_upload_size_allowed(all_files, MAX_TOTAL_ATTACHMENT_SIZE):
            flash('Total attachment size must not exceed 2MB.', 'danger')
            return redirect(url_for('new_request_nda'))

        # Insert into requests table
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO requests (
                user_id, user_name, request_title, document_type, document_value, description,
                type_of_the_agreement, name_of_the_other_parties, Partys_tpdd_status,
                scope_of_work, work_schedule_if_any, performed_by, tenure_value, currency, effective_date,
                amount_to_be_paid, ait, vat, other_costs, total_amount_including_vat_and_tax,
                payment_frequency, advance_payment, security_deposit, security_cheque_or_bank_guarantee,
                penalty_deduction_matrix_for_default, termination_notice_period, consequences_of_termination,
                assets_to_be_returned, name_of_the_notice_receivers, designations_of_receivers,
                notice_receiver_mobile_no, notice_receiver_email, notice_receiver_address,  -- Added columns
                exclusivity, goal_sheet, any_other_special_clause,
                status
            )
            VALUES (
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s,  -- Added values
                %s, %s, %s,
                'supervisor_approval_pending'
            )
        """, (
            user_id, user_name, title, doc_type, doc_value, description,
            type_of_agreement, name_of_other_parties, party_tpdd_status,
            scope_of_work, work_schedule, performed_by, tenure_value, currency, effective_date,
            amount_to_be_paid, ait, vat, other_costs, total_amount,
            payment_frequency, advance_payment, security_deposit, security_cheque,
            penalty_matrix, termination_notice, termination_consequences,
            assets_to_be_returned, name_of_notice_receivers, designations_of_receivers,
            notice_receiver_mobile_no, notice_receiver_email, notice_receiver_address,  # Added variables
            exclusivity, goal_sheet, special_clause
        ))
        mysql.connection.commit()

        # Get inserted request ID
        cur.execute("SELECT LAST_INSERT_ID()")
        request_id = cur.fetchone()[0]

        # Helper function to save files with a specific type
        def save_attachment(file, attachment_type):
            if file and allowed_file(file.filename):
                # Prepend timestamp to filename to avoid collisions
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                original_filename = secure_filename(file.filename)
                filename = f"{timestamp}_{original_filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                cur.execute("""
                    INSERT INTO attachments (request_id, uploaded_by, file_path, attachment_type)
                    VALUES (%s, %s, %s, %s)
                """, (request_id, user_id, filepath, attachment_type))
                mysql.connection.commit()

        save_attachment(details_file, 'initial_request')
        for file in supporting_files:
            save_attachment(file, 'supporting_document')

        # Log request activity
        action_details = "Request submitted by user."
        cur.execute("""
            INSERT INTO request_activity_log (request_id, action_type, performed_by, action_details)
            VALUES (%s, 'request_created', %s, %s)
        """, (request_id, user_id, action_details))
        mysql.connection.commit()

        # --- Send Email Notifications ---
        # Use a DictCursor to fetch user and supervisor emails
        email_cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        email_cur.execute("SELECT email, supervisor_email FROM users WHERE user_id = %s", (user_id,))
        user_info = email_cur.fetchone()
        email_cur.close()

        if user_info:
            user_email = user_info['email']
            supervisor_email = user_info['supervisor_email']
            request_url = url_for('view_request', request_id=request_id, _external=True)

            # 1. Email to the user who made the request
            user_subject = f"LFMS: Confirmation: Your LFMS Request (REQ-{request_id}) is Submitted"
            user_body = f"""
Hello {user_name},

This is a confirmation that your request titled "{title}" has been successfully submitted and sent to your supervisor for approval.

You can view the status of your request here:
{request_url}

Regards,
The LFMS Team
"""
            send_email_async(app, user_email, user_subject, user_body)

            # 2. Email to the supervisor
            if supervisor_email:
                supervisor_subject = f"LFMS: Action Required: New LFMS Request from {user_name} (REQ-{request_id})"
                supervisor_body = f"""
Hello,

A new legal request titled "{title}" from {user_name} requires your approval.

Please review the request details and take action by clicking the link below:
{request_url}

Regards,
The LFMS System
"""
                send_email_async(app, supervisor_email, supervisor_subject, supervisor_body)
        cur.close()

        flash('Your request has been sent for approval. You and your supervisor have been notified by email.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('new_request_fornda.html')


if __name__ == '__main__':
    app.run(debug=True)

