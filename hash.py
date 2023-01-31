from argon2 import PasswordHasher

ph = PasswordHasher()
hash = ph.hash("testPwd")
print(hash) 

print(ph.verify(hash, "testPwd"))