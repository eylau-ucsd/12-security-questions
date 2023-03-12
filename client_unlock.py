from KeyRecoveryScheme import KeyRecoveryScheme
from questions import questions
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES

flag_aes = b'\xbe\xee0\xbc\x8b\x9a\xff\xc9X/:kI\xd6G\xb7\xe3\x02x\xfe$$\x181\xb5\xf0\xb7\x8et\x98\x8f\xfd\x96\xc8\xa0\x00\xd6\x1b}\x93<}\x17\x0b\xc7j\x83,' # flag encrypted in AES-ECB mode (padded with PKCS7), using the key from KeyRecoveryScheme
lock = b'185970976973718392471348762637562487715,67765376276291755327430412650161556119,103782626687727028369068720164474844118,14481914289333650536059889680046946920,1567749643120972073011929787158562638,68707847766207565671135857060692489163,75713119407467155374253206724722242240,185942163089849110183597999767991027618,59293629557125510777251788692384991641,5121899035320906606836603616922516635,59825035957945343912583636769243237256,226731556462292663356213324854672948382'

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
    print("Password recovery successful! Here is your password:")
    print(flag.decode())
except:
    print("Password recovery failed.")