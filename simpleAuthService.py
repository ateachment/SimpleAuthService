from flask import Flask, redirect, request, render_template, make_response
import json 
import requests
from oauthlib.oauth2 import WebApplicationClient
from argon2 import PasswordHasher
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

def roles(roleIDs):
    roles = []
    for roleID in roleIDs:
        if roleID == 1:
            roles.append("Administrator")
        elif roleID == 2:
            roles.append("Viewer")
        else:
            raise Exception("RoleID %d not defined" %(roleID))
    return roles

def decodeJWT(encoded_token):
    public_key = serialization.load_pem_public_key(settings.PUBLIC_KEY, backend=default_backend())
    decoded_token = jwt.decode(encoded_token, public_key, algorithms=["RS256"])
    return decoded_token

def standard_response(page, token):
    decoded_token = decodeJWT(encoded_token=token)
    roleIDs = decoded_token.get("roleIDs")
    print(page)
    resp = make_response(render_template(page, roles = roles(roleIDs)))
    resp.set_cookie('token', token, httponly=True, secure=True)             # cookie can not be read by JavaScript (safer)
    return resp

def standard_get_response(page):
    token = request.cookies.get('token')
    token = json.loads(validate_and_update_token(token)[0])['token']        # validate and update token
    if token == "-1":                                                       # decoding failed 
        return render_template('login.html', message = "Please login.")
    elif token == "-2":                                                     # expired
        return render_template('login.html', message = "Your session has expired. Please login again.")
    else:                                                                   # validated and updated -> Dashboard
        return standard_response(page, token)


# OAuth 2 client setup
client = WebApplicationClient(settings.GOOGLE_CLIENT_ID)

def get_google_provider_cfg():                                              # get google openId endpoints
    return requests.get(settings.GOOGLE_DISCOVERY_URL).json()




@app.route('/')
def index():
    token = request.cookies.get('token')
    token = json.loads(validate_and_update_token(token)[0])['token']        # validate and update token
    if token == "-1":                                                       # decoding failed 
        return render_template('login.html', message = "Please login.")
    elif token == "-2":                                                     # expired
        return render_template('login.html', message = "Your session has expired. Please login again.")
    else:                                                                   # validated and updated -> Dashboard
        return standard_response("dashboard.html", token)


@app.route("/googleLogin")
def login():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["email"],
    )
    return redirect(request_uri)

@app.route("/googleLogin/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Prepare and send a request to get tokens! 
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(settings.GOOGLE_CLIENT_ID, settings.GOOGLE_CLIENT_KEY),
    )

    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))

    # Now that you have tokens (yay) let's find and hit the URL
    # from Google that gives you the user's profile information,
    # including their Google profile image and email
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    #You want to make sure their email is verified.
    # The user authenticated with Google, authorized your
    # app, and now you've verified their email through Google!
    if userinfo_response.json().get("email_verified"):
        users_email = userinfo_response.json()["email"]
    else:
        return "User email not available or not verified by Google.", 400

    # Create a user in db with the information provided by Google if not already exists
    db1 = db.Db()
    query = "SELECT userID FROM tblUser WHERE username = %s" 
    result = db1.execute(query, (users_email,))
    if len(result) == 0:
        query = "INSERT INTO tblUser SET username = %s" 
        result = db1.execute(query, (users_email,))
        db1.commit()
        # only role "Viewer" will be given
        query = "SELECT userID FROM tblUser WHERE username = %s" 
        result = db1.execute(query, (users_email,))
        if(result):         
            userId = result[0][0]                   # i.e. result = [(2,)]
            query = "INSERT INTO tblRoleUser VALUES (%s, 2)" 
            result = db1.execute(query, (userId,))    
            db1.commit()
    del db1                                         # close db connection

    # Login user by creating jwt   
    expiry = dt.datetime.now(tz=timezone.utc) + dt.timedelta(seconds=10) # Expiration 10 seconds in the future     
    token = jwt.encode({"exp": expiry, "roleIDs": [2] }, private_key, algorithm="RS256") 
    
    # Send user back to homepage
    resp = make_response(render_template('dashboard.html'))
    resp.set_cookie('token', token, httponly=True, secure=True)
    return resp         



@app.route('/dashboard', methods=['POST', 'GET'])   
def dashboard():
    if request.method == 'POST':                                            # called by form data of login.html
        token = json.loads(loginUser()[0])['token']                         # loginUser returns i.e. ('{"token": jwt}', 200)
        if token == '-1':                                                   # authentification failed -> login form 
            return render_template('login.html', message = "Wrong username/password.")                     
        else:                                                               # ok -> load dashboard
            return standard_response("dashboard.html", token)
    if request.method == 'GET':                                             # links or redirected by login.html (already logged on)
        return standard_get_response("dashboard.html")

@app.route('/pages/<page>', methods=['GET'])                                # standard page
def load(page):
    return standard_get_response(page)

@app.route('/logout', methods=['POST', 'GET'])   
def logout():
    token = request.cookies.get('token')
    token = json.loads(logoutUser(token)[0])['token']
    resp = make_response(render_template('login.html', message="You have logged out."))
    resp.set_cookie('token', token, httponly=True, secure=True)
    return resp         




#################################################################
# auth service

private_key = serialization.load_pem_private_key(settings.PRIVATE_KEY, password=settings.PASSWORD, backend=default_backend())

jwt_blockedlist = {}

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
    result = db1.execute(query, (username,))
    if(result):
        for row in result:                                          # more than one user with this username possible
            try:                                                    # verify hashed password fail -> throws exception
                if ph.verify(row[1], password) == True:             # check hashed password
                    userId = row[0]                                 # get userId and then roleIDs
                    query2 = "SELECT tblRole.roleID FROM tblRole INNER JOIN tblRoleUser ON tblRole.roleID = tblRoleUser.roleID INNER JOIN tblUser ON tblRoleUser.userID = tblUser.userID WHERE tblUser.userID=%s"
                    result2 = db1.execute(query2, (userId,))
                    del db1                                         # close db connection
                    if(result2):
                        roleIDs = []
                        for row2 in result2:
                            roleIDs.append(row2[0])         
                        expiry = dt.datetime.now(tz=timezone.utc) + dt.timedelta(seconds=10) # Expiration 10 seconds in the future     
                        token = jwt.encode({"exp": expiry, "roleIDs": roleIDs }, private_key, algorithm="RS256") 
                        return json.dumps({ "token": token }), 200  # 200 OK
            except:
                pass
        return json.dumps({ "token": "-1" }), 403                   # 403 forbidden - wrong password
    else:
        return json.dumps({ "token": "-1" }), 403                   # 403 forbidden - no user with this username
   
           
@app.route('/auth/user/<token>', methods=['PUT'])
def validate_and_update_token(token):
    try:
        blocked = jwt_blockedlist.pop(token, None)
        if blocked == None:
            decoded_token = decodeJWT(encoded_token=token)
            roleIDs = decoded_token.get("roleIDs")

            expiry = dt.datetime.now(tz=timezone.utc) + dt.timedelta(seconds=10) # Expiration 10 seconds in the future     
            token = jwt.encode({"exp": expiry, "roleIDs": roleIDs }, private_key, algorithm="RS256")
            return json.dumps({ "token": token }), 200              # 200 token update OK
        else:
            return "{ \"token\": \"-1\" }", 403                     # 403 forbidden
    except jwt.ExpiredSignatureError:                            
        return "{ \"token\": \"-2\" }", 403                         # 403 forbidden (expired)
    except:
        return "{ \"token\": \"-1\" }", 403                         # 403 forbidden (decoding failed for some reasons)

@app.route('/auth/user/<token>', methods=['DELETE'])                # logout
def logoutUser(token):
    try:
        decoded_token = decodeJWT(encoded_token=token)
        exp = decoded_token.get("exp")
        jwt_blockedlist.update({ token : exp })                     # logged out -> token in blockedlist
    except:
        pass
    return "{ \"token\": \"-1\" }", 200                             # 200 logout sucessful

@app.route('/auth/cleanUp', methods=['DELETE'])                     # Webhook: clean up blocked_token_lists
def cleanUp_blocked_token_list():
    print(jwt_blockedlist)
    now = dt.datetime.now(tz=timezone.utc).timestamp() 
    jwts_to_clear = []
    for key in jwt_blockedlist:                                     # Put tokens to be cleaned into a temporary list.
        if jwt_blockedlist[key] < now:                              # They cannot be removed directly because 
            jwts_to_clear.append(key)                               # for loop would throw an exception.
    for key in jwts_to_clear:                                       
        jwt_blockedlist.pop(key)
    print(jwt_blockedlist)
    
    return json.dumps({ "cleanedUp": len(jwts_to_clear) }), 200     # return number of cleaned tokens for testing purposes

if __name__ == '__main__':
    app.run(ssl_context="adhoc")   #  run using https to ensure an encrypted connection with Google (pip install pyOpenSSL)
    
