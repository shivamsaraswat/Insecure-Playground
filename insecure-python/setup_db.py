from main import Post, User, app, db

with app.app_context():
    # First drop all tables to start fresh
    db.drop_all()
    db.create_all()
    
    # Create test user with plain text password
    user = User(username='admin', password='password', role='admin')
    db.session.add(user)
    
    # Create test post
    post = Post(user_id=1, content='Secret post', private=True)
    db.session.add(post)
    
    db.session.commit()
