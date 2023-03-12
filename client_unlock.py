from KeyRecoveryScheme import KeyRecoveryScheme
from questions import questions
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import bcrypt_check

flag_aes = b'\xe0\xcbE\xd4!7\xe1\xdf\x17#C\xb1\x92\xa7\x92\xdc\xdd\x93\x84V\x86\r\x7f\x80\xf1\xaf\xd0Y\xc4\x8e{\xbe\xcbD\xc1\xad\x84\xcd3\x1e-|\x01,\x92U\xdc\xf6' # flag encrypted in AES-ECB mode (padded with PKCS7), using the key from KeyRecoveryScheme
flag_bcrypt = b'$2a$15$I1ivk36Is..emf1NSFwVc.7hP6kBtXaFtn5TE8icHZxkscftDmWFS'
lock = b'96772037615421034685797968900131327620,257995627570530992773640300250845929452,26560812263632337182013022569918906594,247192463880565299369883559093530349763,50057379004943689814052628144341770814,112233149607163743883531854115617268567,157064968171250910631970409603306108841,109239524680706367024485951974070578596,133819439707276950877568241347374334989,45433678570070248450191585464154736162'

print("Welcome to the password recovery wizard!")
print("To recover your password, you will have to answer a series of questions.")
print("You only have to answer 7 of the 10 questions.")
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
    krs = KeyRecoveryScheme(7, 10)
    aes_key = krs.Unlock(answers, lock)
    aes_cipher = AES.new(aes_key, AES.MODE_ECB)
    flag = unpad(aes_cipher.decrypt(flag_aes), 16)
    bcrypt_check(flag, flag_bcrypt)
    print("Password recovery successful! Here is your password:")
    print(flag.decode())
except:
    print("Password recovery failed.")