from KeyRecoveryScheme import KeyRecoveryScheme
from questions import questions
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import bcrypt_check

flag_aes = b'\x18^\xe8\x14\x13 \x9c\xc6\xbe6\xb8\xd4\xdd\x1e\xb6\xed\x96\xbb{\xff0\xb6\xff\xe8\xff\xd8E\x87\xa2\xf4\xab\xa3Gw\xfbb7\xc4\x12b\xd4\r\xf9\xce\xbe\x87L\xc8' # flag encrypted in AES-ECB mode (padded with PKCS7), using the key from KeyRecoveryScheme
flag_bcrypt = b'$2a$15$I1ivk36Is..emf1NSFwVc.7hP6kBtXaFtn5TE8icHZxkscftDmWFS'
lock = b'143265763625422063977786031462129757080,7704516586497010919910726478407977450,191088066748628168526596703587519458790,105388085279923067590076815960461469271,220860402099778277901300722273384386231,79136574627470120386392334260280211399,75665881076807363202915377422160725763,1468732479978230279930515892275384206,106762434207942971140545416170212413825,47829386130954721325152512376328688952,212222336683636732678311742370402877461,256162201228812954263996883357522407578'

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
    bcrypt_check(flag, flag_bcrypt)
    print("Password recovery successful! Here is your password:")
    print(flag.decode())
except:
    print("Password recovery failed.")