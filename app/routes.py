from functools import wraps
import requests, datetime, os, jwt, uuid, json, re
from flask import request, make_response, jsonify
from bson.json_util import dumps
from app import app
from .database.database import users, clientsInfo
from .utils.encrypter import load_key, encrypt, decrypt
from werkzeug.security import generate_password_hash, check_password_hash

config = json.load(open("./config.json"))


# Funcion decoradora que valida el token
def token_required(f):  
    @wraps(f)  
    def validator(*args, **kwargs):
        token = None 
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens'] 

        if not token:  
            return jsonify({'message': 'a valid token is missing'})   

        try:  
            data = jwt.decode(token, config['SECRET_KEY'], algorithms='HS256')
            current_user = users.find_one({'user_id': data['user_id']})
        except Exception as e:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args,  **kwargs)  
    return validator 

# Endpoint del login
@app.route('/login', methods=['POST'])
def login():
    body = request.get_json(force=True)
    if (type(body) == str):
        body = json.loads(body)
    
    bodyUsername = body['username']
    bodyPassword = body['password']

    if not bodyUsername or not bodyPassword:
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    user = users.find_one({'username': bodyUsername})
    if check_password_hash(user['password'], bodyPassword):
        token = jwt.encode({'user_id': user["user_id"], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, config['SECRET_KEY'])
        return jsonify({'token' : token})

    return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})

# Endpoint del register, para crear nuevos usuarios, solo accesible para admins
@app.route('/register', methods=['PUT'])
@token_required
def signup_user(current_user):
    try:
        if (current_user['isAdmin']):
            data = request.get_json()
            hashed_password = generate_password_hash(data['password'], method='sha256')
            new_user = {'user_id': str(uuid.uuid4()), 'username': data['username'], 'password': hashed_password, 'isAdmin': data['isAdmin']}
            users.insert_one(new_user)
            return jsonify({'message': 'registered successfully'})
        else:
            return jsonify({'error': 'Just the admin users can create users'})
    except:
        return jsonify({'error': 'error in the creation of the user'})

# Endpoint data, para consultar la data de los clientes y mostrarla desde el front-end
@app.route('/data', methods=['GET', 'POST'])
@token_required
def fetch_data(current_user):
    if (request.method == 'GET'):
        if (current_user['isAdmin']):
            data = requests.get('https://62433a7fd126926d0c5d296b.mockapi.io/api/v1/usuarios').content
            dataTransformed = json.loads(data.decode('utf-8'))
            try:
                clientsInfo.delete_many({})
                key = load_key()
                for client in dataTransformed:
                    creditCardNumberEncrypted = encrypt(client['credit_card_num'].encode(), key)
                    creditCardCCVEncrypted = encrypt(client['credit_card_ccv'].encode(), key)
                    client['credit_card_num'] = creditCardNumberEncrypted.decode('utf-8')
                    client['credit_card_ccv'] = creditCardCCVEncrypted.decode('utf-8')
                    clientsInfo.insert_one(client)
                return jsonify({'data': 'success'})
            except Exception as error:
                return jsonify({'error': f'{error}'})
        else:
            return jsonify({'error': 'Just the admin users can request data from the server'})
    
    elif (request.method == 'POST'):
        try:
            body = request.get_json()
            if (body != {}):
                body = {'user_name': re.compile(body['user_name'])}
            clients = json.loads(dumps(clientsInfo.find(body)))
            key = load_key()
            clientsLoaded = []
            for client in clients:
                creditCardNumberDecrypted = decrypt(client['credit_card_num'].encode(), key)
                creditCardCCVDecrypted = decrypt(client['credit_card_ccv'].encode(), key)
                client['credit_card_num'] = creditCardNumberDecrypted.decode('utf-8')
                client['credit_card_ccv'] = creditCardCCVDecrypted.decode('utf-8')
                clientsLoaded.append(client)
            
            current_user['_id'] = str(current_user['_id'])

            return jsonify({'clients': clientsLoaded, 'user': current_user, 'success': True})
        except Exception as error:
            return jsonify({'error': f'error during the query of the clients {error}'})
