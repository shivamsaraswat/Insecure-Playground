import base64
import pickle

import jwt
import requests
from flask import Flask, jsonify, render_template_string, request
from flask_sqlalchemy import SQLAlchemy
from lxml import etree

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'  # Hardcoded secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnerable.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Vulnerable User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)  # Storing plain text passwords
    role = db.Column(db.String(20), nullable=False, default='user')
    notes = db.Column(db.Text, nullable=True)  # For stored XSS

# Vulnerable Post Model
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    private = db.Column(db.Boolean, default=False)

with app.app_context():
    db.create_all()

# Vulnerable Authentication - No password hashing, weak JWT
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # SQL Injection vulnerable query
    query = f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'"
    with db.engine.connect() as conn:
        user = conn.execute(db.text(query)).first()

    if user:
        token = jwt.encode({'user_id': user.id, 'role': user.role}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})
    return jsonify({'error': 'Invalid credentials'}), 401

# Broken Object Level Authorization
@app.route('/posts/<int:post_id>', methods=['GET'])
def get_post(post_id):
    # No authentication check
    post = Post.query.get(post_id)
    if post:
        return jsonify({
            'id': post.id,
            'user_id': post.user_id,
            'content': post.content,
            'private': post.private
        })
    return jsonify({'error': 'Post not found'}), 404

# Excessive Data Exposure
@app.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    # Exposing sensitive data including passwords
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'password': user.password,
        'role': user.role
    } for user in users])

# Reflected XSS
@app.route('/search')
def search():
    query = request.args.get('q', '')
    template = f'''
        <h1>Search Results for: {query}</h1>
        <p>No results found.</p>
    '''
    return render_template_string(template)

# Stored XSS
@app.route('/notes', methods=['POST'])
def add_note():
    data = request.get_json()
    user = User.query.get(1)  # Simplified for vulnerability demo
    user.notes = data.get('note')  # Storing unescaped user input
    db.session.commit()
    return jsonify({'message': 'Note added'})

@app.route('/notes/<int:user_id>')
def view_notes(user_id):
    user = User.query.get(user_id)
    if user and user.notes:
        return render_template_string(f"<p>{user.notes}</p>")
    return "No notes found"

# XXE Vulnerability
@app.route('/process-xml', methods=['POST'])
def process_xml():
    xml_data = request.data.decode('utf-8')  # Decode the byte data to string
    try:
        # Create a custom parser that allows external entities
        parser = etree.XMLParser(load_dtd=True, resolve_entities=True)

        # Parse the XML data
        root = etree.fromstring(xml_data, parser=parser)

        # Access the external entity
        xxe_content = root.text  # This will contain the content of the external entity

        return jsonify({'processed': 'success', 'content': xxe_content})
    except Exception as e:
        return jsonify({'error': str(e)})

# Insecure Deserialization
@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    data = base64.b64decode(request.get_json().get('data'))
    obj = pickle.loads(data)  # Vulnerable to pickle deserialization
    return jsonify({'message': 'Data processed', 'content': str(obj)})  # Print the content of the deserialized object

# SSRF Vulnerability
@app.route('/fetch-url')
def fetch_url():
    url = request.args.get('url')
    try:
        response = requests.get(url)  # Vulnerable to SSRF
        return response.text
    except Exception as e:
        return str(e)

# Security Misconfiguration - Debug mode enabled and exposed error messages
app.config['DEBUG'] = True

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
