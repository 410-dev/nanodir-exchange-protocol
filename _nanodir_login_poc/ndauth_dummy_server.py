from flask import Flask, request, jsonify

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

@app.route('/ndauth', methods=['GET'])
def nd_auth():

    USERS: dict = {
        "luke-song": "827ccb0eea8a706c4c34a16891f84e7b", # 12345
        "jin-park": "01cfcd4f6b8770febfb40cb906715822"   # 54321
    }

    # Request url
    requested_url = request.url
    print(f"Received request: {requested_url}")

    # Get base url without path and query parameters
    base_url = request.host_url.rstrip('/')  # Remove trailing slash if exists
    print(f"Base URL: {base_url}")

    PAYLOADS: dict = {
        "luke-song": {
            "permission": ["admin"],
            "user_info": {
                "full_name": "Luke Song",
                "profile-pic": f"{base_url}/static?filename=luke-song-profile.png"
            },
            "files": {
                "$HOME/Desktop/secret.txt": "This is a secret file for Luke Song.",
                "$HOME/Documents/confidential.txt": "This is a confidential document for Luke Song."
            }
        },
        "jin-park": {
            "permission": ["user"],
            "user_info": {
                "full_name": "Jin Park",
                "profile-pic": f"{base_url}/static?filename=jin-park-profile.png"
            },
            "files": {
                "$HOME/Desktop/strategy.txt": "These are some strategy notes for Jin Park.",
                "$HOME/Documents/roadmap.txt": "These are some plans for Jin Park."
            }
        }
    }

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

    if username in USERS and cred == USERS[username]:
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