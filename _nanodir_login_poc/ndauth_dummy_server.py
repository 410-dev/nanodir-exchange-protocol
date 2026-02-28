from flask import Flask, request, jsonify

import json
import hashlib
import base64
import smtplib
from email.message import EmailMessage

app = Flask(__name__)

@app.route("/static", methods=['GET'])
def serve_static():
    # Sends static file in "_images" directory
    filename = request.args.get('filename')
    if not filename:
        return "Filename query parameter is required", 400
    try:
        return app.send_static_file(filename)
    except Exception as e:
        print(f"Error serving file {filename}: {e}")
        return f"Error serving file: {e}", 500

@app.route("/add_acc", methods=['POST'])
def add_acc():
    # Get headers
    headers = request.headers
    print(f"Received add_acc request with query parameters: {request.args} and headers: {headers}")

    # Get full-name, reg-username, reg-password, allow-admin from url query parameters
    full_name = request.args.get('full-name')
    reg_username = request.args.get('username')
    reg_password = request.args.get('password')
    email = request.args.get('email')
    email = base64.b64decode(email).decode('utf-8')
    allow_admin_str = request.args.get('allow-admin', 'false').lower()
    allow_admin = allow_admin_str == 'true'

    # Create user to users.json
    try:
        with open("users.json", "r") as f:
            db = json.load(f)

        if "auth" not in db:
            db["auth"] = {}

        if reg_username in db["auth"]:
            return jsonify({
                "status": "error",
                "message": "Username already exists"
            }), 400

        db["auth"][reg_username] = hashlib.md5(reg_password.encode()).hexdigest()

        # Payload
        if "payloads" not in db:
            db["payloads"] = {}

        db["payloads"][reg_username] = {
            "permission": "admin" if allow_admin else "user",
            "user_info": {
                "full_name": full_name
            }
        }

        with open("users.json", "w") as f:
            json.dump(db, f, indent=4)
    except Exception as e:
        print(f"Error adding account: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error adding account: {e}"
        }), 500

    print("Account added successfully, sending email notification...")

    msg = EmailMessage()
    content = f"""This email is sent from AEONS Server.
    
Your account is created and active in current AEONS Domain Controller.
    
Account Information:
- Full Name: {full_name}
- Username: {reg_username}
- Ownership: {email}
- Permission: {"Admin" if allow_admin else "User"}
- Initial Password: {reg_password}

You are now allowed to logon to machines connected AEONS Domain Controller.

You may configure your account information in: https://accounts.acadia.team/ (coming soon)
    """
    msg.set_content(content)
    msg['Subject'] = "AEONS Server DC: New Account Added"
    msg['From'] = "noreply-aeons@acadia.team"
    msg['To'] = email

    # Server configuration
    smtp_server = "smtp.migadu.com"
    port = 587  # For STARTTLS
    sender_email = "noreply-aeons@acadia.team"
    password = "Nahrooter0129!"

    print(f"Connecting to SMTP server {smtp_server} on port {port} to send email to {email}...")

    try:
        # Create a secure connection and send email
        print("Establishing connection to SMTP server...")
        server = smtplib.SMTP(smtp_server, port)
        print("Connection established, starting TLS...")
        server.starttls()  # Secure the connection
        print("TLS established")
        server.login(sender_email, password)
        print("Logged in to SMTP server")
        server.send_message(msg)
        print("Email sent successfully")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        print("Closing SMTP server connection")
        server.quit()

    return jsonify({
        "status": "OK",
        "message": "Account added successfully"
    })

@app.route('/ndauth', methods=['GET'])
def nd_auth():

    # Get from users.json
    with open("users.json", "r") as f:
        db = json.load(f)

    USERS: dict = db.get("auth")

    # Request url
    requested_url = request.url
    print(f"Received request: {requested_url}")

    # Get base url without path and query parameters
    base_url = request.host_url.rstrip('/')  # Remove trailing slash if exists
    print(f"Base URL: {base_url}")

    PAYLOADS: dict = db.get("payloads", {})

    # Retrieve query parameters from the URL
    machine_name = request.args.get('machine_name')
    username = request.args.get('username')
    otp = request.args.get('otp')
    cred = request.args.get('cred')

    # Basic validation: Check if all parameters are present
    if not all([machine_name, username, otp]):
        return jsonify({
            "status": "error",
            "message": "Missing required parameters"
        }), 400

    # Logic placeholder: This is where you'd verify the OTP
    print(f"Auth request for {username} on {machine_name} with OTP {otp} and cred {cred}")

    # If user credentials in the database is "REVOKED", set status to REVOKED and authenticated to False
    if username in USERS and USERS[username] == "REVOKED":
        print(f"User {username} is revoked.")
        response_data = {
            "status": "REVOKED",
            "authenticated": False,
            "user_context": {
                "machine": machine_name,
                "user": username
            },
            "payload": {}
        }
        return jsonify(response_data)

    if username in USERS and cred == USERS[username]:

        # Traverse payloads for user and replace {base_url} with actual base url
        if username in PAYLOADS:
            for key, value in PAYLOADS[username].items():
                if isinstance(value, str):
                    PAYLOADS[username][key] = value.replace("{base_url}", base_url)
                elif isinstance(value, list):
                    PAYLOADS[username][key] = [v.replace("{base_url}", base_url) if isinstance(v, str) else v for v in value]
                elif isinstance(value, dict):
                    for k, v in value.items():
                        if isinstance(v, str):
                            PAYLOADS[username][key][k] = v.replace("{base_url}", base_url)

        print(f"User {username} authenticated successfully.")

        response_data = {
            "status": "OK",
            "authenticated": True,
            "user_context": {
                "machine": machine_name,
                "user": username
            },
            "payload": PAYLOADS.get(username, {})
        }
    else:
        print(f"User {username} failed authentication.")
        response_data = {
            "status": "OK",
            "authenticated": False,
            "user_context": {}
        }

    return jsonify(response_data)

if __name__ == '__main__':
    # Run on port 80 or 8080 depending on your needs
    app.run(host='0.0.0.0', port=65500, debug=True)