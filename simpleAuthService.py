from flask import Flask, request
import json

# make cross-origin AJAX possible because of using swagger editor
# https://flask-cors.readthedocs.io/en/latest/#using-json-with-cors
from flask_cors import CORS, cross_origin  
 
app = Flask(__name__)
CORS(app)  # make cross-origin AJAX possible

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
    
    if username == "testUser" and password == "testPwd":            # Everything is OK
        return "{ \"token\": \"123456\" }"                          # JavaScript JSON parse don’t support single quote.
    else:
        return "{ \"token\": \"-1\" }", 403            # Forbidden


Logout todo




if __name__ == '__main__':
    app.run()