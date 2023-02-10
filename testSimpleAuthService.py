import json
from simpleAuthService import app

def test_login_json_sucess():
    data =  {
                "username": "testUser",
                "password": "testPwd"
            }
    response = app.test_client().post('/auth/user/login', json=data)
    assert response.status_code == 200
    token = json.loads(response.data.decode('utf-8')).get("token")
    assert token == '123456'

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
    token = json.loads(response.data.decode('utf-8')).get("token")
    assert token == '123456'

def test_logout():
    response = app.test_client().delete('/auth/user/123456')
    assert response.status_code == 200
    token = json.loads(response.data.decode('utf-8')).get("token")
    assert token == '-1'


