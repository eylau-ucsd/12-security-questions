from KeyRecoveryScheme import KeyRecoveryScheme
from questions import questions
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import bcrypt

print("Welcome to the password recovery wizard!")
password = input("Enter the password you want to recover later on: ") # the password is the flag
print("Next, you will have to answer a series of 12 questions. The answers to these questions will be used to secure your password.")
print("We will begin the questions now.")
print()

answers = []
for i in range(len(questions)):
    ans = str(input(questions[i] + " "))
    answers.append((i + 1, ans)) # (i + 1) because the question # is 1-indexed

krs = KeyRecoveryScheme(10, 12)
(aes_key, lock) = krs.Lock(answers)
aes_cipher = AES.new(aes_key, AES.MODE_ECB)
encrypted_password = aes_cipher.encrypt(pad(password.encode(), 16))
password_hash = bcrypt(password, 15)

print(f"Encrypted password: {str(encrypted_password)}")
print(f"Password hash: {password_hash}")
print(f"Lock: {lock}")