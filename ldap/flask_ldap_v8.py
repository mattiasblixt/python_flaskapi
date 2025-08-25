'''
flask_ldap_v8.py
'''
import os
from flask import Flask
from flask_jwt_extended import JWTManager
from auth_v8 import auth_bp
from users_v8 import users_bp
from access_groups_v8 import access_groups_bp

app = Flask(__name__)

# Configure JWT
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key')  # Change in production
jwt = JWTManager(app)

# Register Blueprints
app.register_blueprint(auth_bp, url_prefix='/api')
app.register_blueprint(users_bp, url_prefix='/api')
app.register_blueprint(access_groups_bp, url_prefix='/api')

if __name__ == '__main__':
    app.run(debug=True)
