import hashlib

# test hashlib
print(hashlib.sha512(str("testPwd").encode('utf-8')).hexdigest())