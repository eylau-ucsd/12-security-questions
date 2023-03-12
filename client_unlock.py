from KeyRecoveryScheme import KeyRecoveryScheme
from questions import questions
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from data import flag_aes, lock, flag_sha256 # the data.py file is dynamically generated

print("Welcome to the password recovery wizard!")
print("To recover your password, you will have to answer a series of questions.")
print("You only have to answer 10 of the 12 questions.")
print("To skip a question, simply hit Return without entering any input.")
print("We will begin the questions now.")
print()

answers = []
for i in range(len(questions)):
    ans = str(input(questions[i] + " "))
    if (ans == ""):
        continue
    answers.append((i + 1, ans)) # (i + 1) because the question # is 1-indexed

try:
    krs = KeyRecoveryScheme(10, 12)
    aes_key = krs.Unlock(answers, lock)
    aes_cipher = AES.new(aes_key, AES.MODE_ECB)
    flag = unpad(aes_cipher.decrypt(flag_aes), 16)
    if (flag_sha256 == SHA256.new(data=flag).digest()):
        print("Password recovery successful! Here is your password:")
        print(flag.decode())
    else:
        print("The hash of the recovered password doesn't match the expected hash of the password.")
        print("Password recovery failed.")
except ValueError:
    print("There was an error in unpadding.")
    print("Password recovery failed.")
except AssertionError:
    print(f"You need to answer at least 10 security questions to recover the password, but you only gave {len(answers)} answers.")
    print("Password recovery failed.")