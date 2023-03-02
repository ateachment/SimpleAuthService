import settings
import jwt
import pyotp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import json
import time
import db
from simpleAuthService import app

encoded_token = ""

# reset totpActivated
db1 = db.Db()
query = "UPDATE tblUser SET totpActivated = FALSE WHERE userID = %s"
result = db1.execute(query, (1,))
db1.commit()
del db1 


def decodeJWT(encoded_token):
    public_key = serialization.load_pem_public_key(settings.PUBLIC_KEY, backend=default_backend())
    decoded_token = jwt.decode(encoded_token, public_key, algorithms=["RS256"])
    return decoded_token


#first factor authentification
def test_login1_json_sucess():
    data =  {
                "username": "testUser",
                "password": "testPwd" 
            }
    response = app.test_client().post('/auth/user/login1', json=data)
    assert response.status_code == 200 

    encoded_token = json.loads(response.data.decode('utf-8')).get("token")
    decoded_token = decodeJWT(encoded_token=encoded_token)

    roleIDs = decoded_token.get("roleIDs")
    assert roleIDs == [1, 2]

def test_login1_json_fail():
    data =  {
                "username": "testUser",
                "password": "testWrongPwd"
            }
    response = app.test_client().post('/auth/user/login1', json=data)
    assert response.status_code == 403
    token = json.loads(response.data.decode('utf-8')).get("token")
    assert token == '-1'

def test_login1_form_success():
    data = "username=testUser&password=testPwd"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = app.test_client().post('/auth/user/login1', data=data, headers=headers)
    assert response.status_code == 200
    
    totpActivated = json.loads(response.data.decode('utf-8')).get("totpActivated")
    uri = json.loads(response.data.decode('utf-8')).get("uri")
    assert totpActivated == 0   # false
    # Debug mode activ: key not generated randomly -> uri const.
    assert uri == "otpauth://totp/SimpleAuthService:testUser?secret=CautionDebugModeTrueKeyIsNotGood&issuer=SimpleAuthService"        

    global encoded_token 
    encoded_token = json.loads(response.data.decode('utf-8')).get("token")
    decoded_token = decodeJWT(encoded_token=encoded_token)

    userId = decoded_token.get("userId")
    roleIDs = decoded_token.get("roleIDs")
    assert userId == 1
    assert roleIDs == [1, 2]


# second factor authentication
def test_login2_form_success():
    global encoded_token

    totp = pyotp.TOTP('CautionDebugModeTrueKeyIsNotGood')
    data = "totpCode=" + totp.now()                 # => i.e '492039'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    client = app.test_client()
    client.set_cookie("localhost", "token", encoded_token)
    response = client.post('/auth/user/login2', data=data, headers=headers)
    assert response.status_code == 200

    encoded_token = json.loads(response.data.decode('utf-8')).get("token")
    decoded_token = decodeJWT(encoded_token=encoded_token)

    roleIDs = decoded_token.get("roleIDs")
    assert roleIDs == [1, 2]





def test_logout():
    response = app.test_client().delete('/auth/user/' + encoded_token)
    assert response.status_code == 200
    token = json.loads(response.data.decode('utf-8')).get("token")
    assert token == '-1'


def test_cleanUp_blocked_token_list():
    response = app.test_client().delete('/auth/cleanUp')
    assert response.status_code == 200
    cleanedUp = json.loads(response.data.decode('utf-8')).get("cleanedUp")
    assert cleanedUp == 0             # direct clean up of blocked jwts -> nothing has to be done

def test_cleanUp_blocked_token_list2():
    time.sleep(settings.EXPIRY_TIME_SECONDS)
    response = app.test_client().delete('/auth/cleanUp')
    assert response.status_code == 200
    cleanedUp = json.loads(response.data.decode('utf-8')).get("cleanedUp")
    assert cleanedUp == 1     # settings.EXPIRY_TIME_SECONDS later blocked jwt can be removed from the blocked list



