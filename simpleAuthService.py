from flask import Flask, request, render_template, make_response
import json
from argon2 import PasswordHasher
import secrets
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
        dictResponse = json.loads(autorize(token)[0])
        roleIDs = dictResponse['roleIDs']
        if roleIDs == "-1":
            return render_template('login.html', message = "Your session has expired. Please login again.")
        else:
            resp = make_response(render_template('dashboard.html', roles = roles(roleIDs)))
        return resp

@app.route('/dashboard', methods=['POST', 'GET'])   
def dashboard():
    if request.method == 'POST':                    # called by form data of login.html
        dictResponse = json.loads(loginUser()[0])   # loginUser returns i.e. ('{"token": "123456"}', 200)
        token = dictResponse['token']
        if token == '-1':                           # authentification failed -> login form 
            return render_template('login.html', message = "Wrong username/password.")                     
        else:                                       # ok -> load dashboard
            dictResponse = json.loads(autorize(token)[0])
            roleIDs = dictResponse['roleIDs']
            resp = make_response(render_template('dashboard.html', roles = roles(roleIDs)))
            resp.set_cookie('token',token)
        return resp
    if request.method == 'GET':               # links or redirected by login.html (already logged on)
        token = request.cookies.get('token')
        dictResponse = json.loads(autorize(token)[0]) # AUTORIZATION
        roleIDs = dictResponse['roleIDs']
        if roleIDs == "-1":
            return render_template('login.html', message = "Your session has expired. Please login again.")
        else:
            resp = make_response(render_template('dashboard.html', roles = roles(roleIDs)))
        return resp
        
@app.route('/pages/<page>', methods=['GET'])   
def load(page):
    token = request.cookies.get('token')
    dictResponse = json.loads(autorize(token)[0]) # AUTORIZATION
    roleIDs = dictResponse['roleIDs']
    if roleIDs == "-1":
        return render_template('login.html', message = "Your session has expired. Please login again.")
    else:
        resp = make_response(render_template(page, roles = roles(roleIDs)))
    return resp


@app.route('/logout', methods=['POST', 'GET'])   
def logout():
    token = request.cookies.get('token')
    dictResponse = json.loads(logoutUser(token)[0])  # logoutUser returns ('{"token": "-1"}', 200)
    token = dictResponse['token']
    if token == '-1':                           # logout sucessful -> login form 
        resp = make_response(render_template('login.html', message="You have logged out."))
        resp.set_cookie('token','-1')
        return resp                     





#################################################################
# auth service

def generateToken():
    if settings.DEBUG_MODE:
        return "123456"                     # testing environment
    else:
        return secrets.token_urlsafe(64)    # production

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
    ph = PasswordHasher()
    query = "SELECT userId, pwd FROM tblUser WHERE username=%s"
    result = db1.execute(query,(username,))
    if(result):
        for row in result:                                          # more than one user with this username possible
            try:                                                    # verify hashed password fail -> throws exception
                if ph.verify(row[1], password) == True:             # check hashed password
                    userId = row[0]                                 
                    token = generateToken()
                    query = "UPDATE tblUser SET token = %s WHERE userID = %s" 
                    result = db1.execute(query, (token, userId))
                    db1.commit()                                    # actually execute
                    return json.dumps({ "token": token }), 200      # 200 OK
            except:
                pass
        return json.dumps({ "token": "-1" }), 403                   # 403 forbidden - wrong password
    else:
        return json.dumps({ "token": "-1" }), 403                   # 403 forbidden - no user with this username
    del db1                                                         # close db connection
                                                    
                                                    
@app.route('/auth/user/<token>', methods=['DELETE'])
def logoutUser(token):
    db1 = db.Db()
    query = "UPDATE tblUser SET token = '-1' WHERE token=%s" 
    result = db1.execute(query, (token,))
    db1.commit()      
    del db1       
    return "{ \"token\": \"-1\" }", 200                             # 200 logout sucessful

@app.route('/auth/user/roles/<token>', methods=['GET'])
def autorize(token):
    db1 = db.Db()
    # Update timestamp or make token invalid
    query = "UPDATE tblUser SET tokenExpiry = CURRENT_TIMESTAMP WHERE tokenExpiry >= (NOW() - INTERVAL 10 SECOND) AND token <> '-1' AND token=%s" 
    result = db1.execute(query, (token,))
    query = "UPDATE tblUser SET token = '-1' WHERE tokenExpiry < (NOW() - INTERVAL 10 SECOND) AND token <> '-1' AND token=%s" 
    result = db1.execute(query, (token,))  
    db1.commit()
    query = "SELECT tblRole.roleID FROM tblRole INNER JOIN tblRoleUser ON tblRole.roleID = tblRoleUser.roleID INNER JOIN tblUser ON tblRoleUser.userID = tblUser.userID WHERE token <> '-1' AND token = %s" 
    result = db1.execute(query, (token,))        # i.e. [(1,), (2,)] or []
    if(result):                        # role(s) available
        roleIDs = []
        for row in result:
            roleIDs.append(row[0])                                          
        return json.dumps({ "roleIDs": roleIDs }), 200
    else:
        return json.dumps({ "roleIDs": "-1" }), 403     # forbidden
    del db1       

if __name__ == '__main__':
    app.run()