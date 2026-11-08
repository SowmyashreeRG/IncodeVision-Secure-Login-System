Secure Login System

A web-based authentication application developed as part of the IncodeVision Cyber Security Internship.

Technologies Used

- Python
- Flask
- SQLite
- HTML and CSS
- Werkzeug

Features

- User registration and login
- Secure password hashing
- Failed login attempt tracking
- Account lockout after repeated failed attempts
- Session management
- Protected dashboard and logout

How to Run

1. Install the required packages:
   pip install -r requirements.txt

2. Set the Flask secret key in PowerShell: 
   $env:SECRET_KEY = "your-secret-key"

3. Start the application on port 5001:
   python -c "from app import app; app.run(host='127.0.0.1', port=5001)"

4. Open this URL in your browser:
   "http://127.0.0.1:5001/login"

GitHub Repository

https://github.com/SowmyashreeRG/IncodeVision-Secure-Login-System