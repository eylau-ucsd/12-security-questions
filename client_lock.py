from KeyRecoveryScheme import KeyRecoveryScheme
from questions import questions
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

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

print("\nGenerated the following configuration for the password safe:")
print("--------------------------------------------------------------")
print(f"flag_aes = {str(encrypted_password)}")
print(f"lock = {str(lock)}")
print(f"flag_sha256 = {str(SHA256.new(data=password.encode()).digest())}")
print("--------------------------------------------------------------")
print("\nCopy and paste the 3 lines in between the horizontal bars and paste them into data.py.")