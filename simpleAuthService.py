from flask import Flask, request, render_template, make_response
import json 
import hashlib
import jwt 
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import datetime as dt
from datetime import timezone, timedelta
import db
import settings
# make cross-origin AJAX possible because of using swagger editor
# https://flask-cors.readthedocs.io/en/latest/#using-json-with-cors
from flask_cors import CORS

app = Flask(__name__)

if settings.DEBUG_MODE:
    CORS(app)                               # make cross-origin AJAX possible 


#################################################################
# user interface

def decodeJWT(encoded_token):
    public_key = serialization.load_pem_public_key(settings.PUBLIC_KEY, backend=default_backend())
    decoded_token = jwt.decode(encoded_token, public_key, algorithms=["RS256"])
    return decoded_token

def roles(roleIDs):
    roles = []
    for roleID in roleIDs:
        if roleID == 1:
            roles.append("Administrator")
        elif roleID == 2:
            roles.append("Viewer")
        else:
            raise Exception("RoleID %i not defined")
    return roles
            

@app.route('/')
def index():
    token = request.cookies.get('token')
    if token == "-1":
        return render_template('login.html', message = "Please login.")
    elif token == None:
        return render_template('login.html', message = "Please login.")
    else:
        try:
            decoded_token = decodeJWT(encoded_token=token)
            roleIDs = decoded_token.get("roleIDs")
            return make_response(render_template('dashboard.html', roles = roles(roleIDs)))
        except jwt.ExpiredSignatureError:
            return render_template('login.html', message = "Your session has expired. Please login again.")
        except:
            return render_template('login.html', message = "Please login.")

@app.route('/dashboard', methods=['POST', 'GET'])   
def dashboard():
    if request.method == 'POST':                    # called by form data of login.html
        dictResponse = json.loads(loginUser()[0])   # loginUser returns i.e. ('{"token": jwt}', 200)
        token = dictResponse['token']
        if token == '-1':                           # authentification failed -> login form 
            return render_template('login.html', message = "Wrong username/password.")                     
        else:                                       # ok -> load dashboard
            try:
                decoded_token = decodeJWT(encoded_token=token)
                roleIDs = decoded_token.get("roleIDs")
                resp = make_response(render_template('dashboard.html', roles = roles(roleIDs)))
                resp.set_cookie('token',token)
                return resp
            except jwt.ExpiredSignatureError:
                return render_template('login.html', message = "Your session has expired. Please login again.")
            except:
                return render_template('login.html', message = "Please login.")
    if request.method == 'GET':               # links or redirected by login.html (already logged on)
        token = request.cookies.get('token')
        try:
            decoded_token = decodeJWT(encoded_token=token)
            roleIDs = decoded_token.get("roleIDs")
            return make_response(render_template('dashboard.html', roles = roles(roleIDs)))
        except jwt.ExpiredSignatureError:
            return render_template('login.html', message = "Your session has expired. Please login again.")
        except:
            return render_template('login.html', message = "Please login.")
        
@app.route('/pages/<page>', methods=['GET'])   
def load(page):
    token = request.cookies.get('token')
    try:
        decoded_token = decodeJWT(encoded_token=token)
        roleIDs = decoded_token.get("roleIDs")
        return make_response(render_template(page, roles = roles(roleIDs)))
    except jwt.ExpiredSignatureError:
        return render_template('login.html', message = "Your session has expired. Please login again.")
    except:
        return render_template('login.html', message = "Please login.")

@app.route('/logout', methods=['POST', 'GET'])   
def logout():
    token = request.cookies.get('token')
    try:
        decoded_token = decodeJWT(encoded_token=token)
    except:
        pass
    l
    resp = make_response(render_template('login.html', message="You have logged out."))
    resp.set_cookie('token','-1')
    return resp         




#################################################################
# auth service

private_key = serialization.load_pem_private_key(settings.PRIVATE_KEY, password=settings.PASSWORD, backend=default_backend())

jwt_blacklist = {}

@app.route('/auth/user/login', methods=['POST'])
def loginUser():
    content_type = request.headers.get('Content-Type')
    if content_type == 'application/json':
        username = request.json['username']
        password = request.json['password']
    elif (content_type == 'application/x-www-form-urlencoded'):     # regular html form data
        username = request.form['username']
        password = request.form['password']
    else:
        return 'Content-Type not supported: ' + content_type, 400   # Bad request
    
    db1 = db.Db()
    hashedPW = hashlib.sha512(str(password).encode('utf-8')).hexdigest()
    query = "SELECT tblRole.roleID FROM tblRole INNER JOIN tblRoleUser ON tblRole.roleID = tblRoleUser.roleID INNER JOIN tblUser ON tblRoleUser.userID = tblUser.userID WHERE username='%s' AND pwd='%s'" %(username, hashedPW)
    result = db1.execute(query)
    del db1                                                         # close db connection                                           
    if(result):
        roleIDs = []
        for row in result:
            roleIDs.append(row[0])         
        expiry = dt.datetime.now(tz=timezone.utc) + dt.timedelta(seconds=10) # Expiration 10 seconds in the future     
        token = jwt.encode({"exp": expiry, "roleIDs": roleIDs }, private_key, algorithm="RS256")
        jwt_blacklist.update({ token:expiry })
        return json.dumps({ "token": token }), 200                  # 200 OK
    else:
        return json.dumps({ "token": "-1" }), 403                   # 403 forbidden
                            
@app.route('/auth/user/<token>', methods=['DELETE'])
def logoutUser(token):
    if jwt_blacklist.get(token):
        jwt_blacklist.pop(token)
    return "{ \"token\": \"-1\" }", 200                             # 200 logout sucessful

if __name__ == '__main__':
    app.run()