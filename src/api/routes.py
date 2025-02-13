"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, Users
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required
from werkzeug.security import generate_password_hash, check_password_hash


api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)

@api.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    identity = get_jwt_identity()
    print('user identity->', identity)
    user = Users.query.get(id)
    return jsonify({"msg":"OK", "user": user.serialize()})




# ---------------------USERS---------------------
@api.route('/users', methods=['GET'])
def get_users():
    data = Users.query.all()
    users = [users.serialize() for users in data]
    
    return jsonify({"msg":"OK", "data":users}), 200



@api.route('/users', methods=['POST'])
def create_users():
    email = request.json.get('email', None)
    password = request.json.get('password', None)

    if not email or not password:
        return jsonify({"msg": "All fields already exist"}), 400
    
    check = Users.query.filter_by(email=email).first()

    if check:
        return jsonify({"msg": "User already exist"}), 400

    new_user = Users(email=email, password=password, is_active = True)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"msg": "OK", "data": new_user.serialize()}), 201



# ---------------------USER---------------------

@api.route('/user', methods=['GET'])
def user():
    email = request.json.get('email', None)
    exist = Users.query.filter_by(email=email).first()

    if exist is None:
        return jsonify({"msg": f"No user found {exist.email}"}), 404
    
    return jsonify({"msg": "one user with email" + str(email), "user": exist.serialize()}), 200



@api.route('/register', methods=['GET'])
def register():
    email = request.json.get('email', None)
    password = request.json.get('password', None)
    is_active = request.json.get('is_active', None)

    if not email or not password:
        return jsonify({"msg": "missing data"});

    exist = Users.query.filter_by(email=email).first()
    if exist:
        return jsonify({"msg": "email taken"})
    hashed_password = generate_password_hash(password)
    new_user = Users(email=email, password=hashed_password, is_active=is_active)

    db.session.add(new_user)
    db.session.commit()

    token = create_access_token(identity=str(new_user.id))

    return jsonify({"msg": 'ok', 'token': token})



@api.route('/login', methods=['POST'])
def login():
    email = request.json.get('email', None)
    password = request.json.get('password', None)

    if not email or not password:
        return jsonify({"msg": "missing data"}), 400
    
    exist = Users.query.filter_by(email=email).first()
    if not exist: 
        return jsonify({"msg": "User doesnt exist"})
    
    check_password_hash(exist.password, password), 400
    if not check_password_hash:
        return jsonify({"msg": "Incorrect password"})