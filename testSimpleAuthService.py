import pytest 
import settings
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import json
from simpleAuthService import app

encoded_token = ""

def decodeJWT(encoded_token):
    public_key = serialization.load_pem_public_key(settings.PUBLIC_KEY, backend=default_backend())
    decoded_token = jwt.decode(encoded_token, public_key, algorithms=["RS256"])
    return decoded_token

def test_login_json_sucess():
    data =  {
                "username": "testUser",
                "password": "testPwd" 
            }
    response = app.test_client().post('/auth/user/login', json=data)
    assert response.status_code == 200 

    encoded_token = json.loads(response.data.decode('utf-8')).get("token")
    decoded_token = decodeJWT(encoded_token=encoded_token)

    roleIDs = decoded_token.get("roleIDs")
    assert roleIDs == [1, 2]

def test_login_json_fail():
    data =  {
                "username": "testUser",
                "password": "testWrongPwd"
            }
    response = app.test_client().post('/auth/user/login', json=data)
    assert response.status_code == 403
    token = json.loads(response.data.decode('utf-8')).get("token")
    assert token == '-1'

def test_login_form_success():
    data = "username=testUser&password=testPwd"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = app.test_client().post('/auth/user/login', data=data, headers=headers)
    assert response.status_code == 200

    global encoded_token 
    encoded_token = json.loads(response.data.decode('utf-8')).get("token")
    decoded_token = decodeJWT(encoded_token=encoded_token)

    roleIDs = decoded_token.get("roleIDs")
    assert roleIDs == [1, 2]

def test_logout():
    response = app.test_client().delete('/auth/user/' + encoded_token)
    assert response.status_code == 200
    token = json.loads(response.data.decode('utf-8')).get("token")
    assert token == '-1'


def cleanUp_blocked_token_list():
    assert "x" == encoded_token
    response = app.test_client().delete('/auth/cleanUp')
    assert response.status_code == 200
    cleanedUp = json.loads(response.data.decode('utf-8')).get("cleanedUp")
    assert cleanedUp == 1

