from flask import Flask, request
import json
from argon2 import PasswordHasher
import secrets
import db
import settings
# make cross-origin AJAX possible because of using swagger editor
# https://flask-cors.readthedocs.io/en/latest/#using-json-with-cors
from flask_cors import CORS, cross_origin  


def generateToken():
    if settings.DEBUG_MODE:
        return "123456"                     # testing environment
    else:
        return secrets.token_urlsafe(64)    # production

app = Flask(__name__)

if settings.DEBUG_MODE:
    CORS(app)           # make cross-origin AJAX possible 

@app.route('/auth/user/login', methods=['POST'])
def loginUser():
    content_type = request.headers.get('Content-Type')
    if content_type == 'application/json':
        print(request)
        username = request.json['username']
        password = request.json['password']
    elif (content_type == 'application/x-www-form-urlencoded'):     # regular html form data
        username = request.form['username']
        password = request.form['password']
    else:
        return 'Content-Type not supported: ' + content_type, 400   # Bad request
    
    db1 = db.Db()
    ph = PasswordHasher()
    query = "SELECT userId, pwd FROM tblUser WHERE username='%s'" %(username)
    result = db1.execute(query)
    if(result):
        for row in result:                                          # more than one user with this username possible
            try:                                                    # verify hashed password fail -> throws exception
                if ph.verify(row[1], password) == True:             # check hashed password
                    userId = row[0]                                 
                    token = generateToken()
                    query = "UPDATE tblUser SET token = '%s' WHERE userID=%d" %(token, userId)
                    result = db1.execute(query)
                    db1.commit()                                    # actually execute
                    return json.dumps({ "token": token })           # 200 OK
            except:
                pass
        return json.dumps({ "token": "-1" }), 403                   # 403 forbidden - wrong password
    else:
        return json.dumps({ "token": "-1" }), 403                   # 403 forbidden - no user with this username
    del db1                                                         # close db connection
                                                    
                                                    
@app.route('/auth/user/<token>', methods=['DELETE'])
def logoutUser(token):
    db1 = db.Db()
    query = "UPDATE tblUser SET token = '-1' WHERE token=%s" %(token)
    result = db1.execute(query)
    db1.commit()      
    del db1       
    return "{ \"token\": \"-1\" }"                                  # 200 logout sucessful


if __name__ == '__main__':
    app.run()