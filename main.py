import socket
from Crypto.Cipher import AES
from Crypto.Util import Padding
import random
import string

#Functie XOR
def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

#Generare random
def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

KCBC = b"qwertyuiopasdfgh"
KCFB = b"zxcvbnmlkjhgfdsa"
KAES = b"1234567890123456"

#Criptare cu AES
def CriptwAES(text,key):
    cipher = AES.new(key,AES.MODE_ECB)
    cript = cipher.encrypt(Padding.pad(text,16,'pkcs7'))
    return cript

#Decriptare cu AES
def DecriptwAES(text,key):
    cipher = AES.new(key,AES.MODE_ECB)
    decript = cipher.decrypt(text)
    return Padding.unpad(decript,16,'pkcs7')

#Criptare cu CBC
def CriptwCBC(text, key, vector):
    text = bytes(text)
    cript = b''
    blocks = [text[i:i + 8] for i in range(0, len(text), 8)]
    for i in blocks:
        cript += CriptwAES(byte_xor(i,vector),key)
        vector = CriptwAES(byte_xor(i,vector),key)
    return cript

#Decriptare cu CBC
def DecriptwCBC(ctext, key, vector):
    decript = b''
    blocks = [ctext[i:i + 16] for i in range(0, len(ctext), 16)]
    for i in blocks:
        seq = DecriptwAES(i, key)
        decript += byte_xor(seq, vector)
        vector = i
    return decript

#Criptare cu CFB
def CriptwCFB(text, key, vector):
    text = bytes(text)
    cript = b''
    blocks = [text[i:i + 8] for i in range(0, len(text), 8)]
    for i in blocks:
        i = Padding.pad(i,16,'pkcs7')
        seq = CriptwAES(vector, key)
        cript += byte_xor(i,seq)
        vector = byte_xor(i,seq)
    return cript

#Decriptare cu CFB
def DecriptwCFB(ctext, key, vector):
    decript = b''
    blocks = [ctext[i:i + 16] for i in range(0, len(ctext), 16)]
    for i in blocks:
        seq = CriptwAES(vector,key)
        decript += Padding.unpad(byte_xor(seq,i),16,'pkcs7')
        vector = i
    return decript

print("Serverul a fost pornit")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((socket.gethostname(),1234))

#Asteptam primul client
s.listen()
client1, address_client1 = s.accept()
print(f"Conectarea de la {address_client1} a fost efectuata!")
client1.send(bytes("Bine ai venit pe server. \nAcum asteapta ca alt client sa se conecteze pe server pentru a putea comunica.", "utf-8"))

#Asteptam al doilea client
s.listen()
client2, address_client2 = s.accept()
print(f"Conectarea de la {address_client2} a fost efectuata!")
client2.send(bytes("Bine ai venit pe server. \nCelalalt client deja este conectat. Puteti comunica.", "utf-8"))

#Anuntam primul client ca al doilea client s-a conectat
client1.send(bytes("gata","utf-8"))

#Asteptam de la primul client modul de operare
msg = client1.recv(8)

# Comunicarea in CBC
if msg.decode("utf-8") == 'CBC':
    print("S-a ales modul CBC")
    client2.send(bytes("CBC","utf-8"))
    VI = bytes(get_random_string(16), 'utf-8')
    criptedCBCKey = CriptwAES(KCBC,KAES)
    criptedVI = CriptwAES(VI,KAES)
    client1.send(criptedCBCKey)
    client1.send(criptedVI)
    client2.send(criptedCBCKey)
    client2.send(criptedVI)
    confirm1 = client1.recv(64)
    confirm2 = client2.recv(64)
    confirm1 = DecriptwCBC(confirm1,KCBC,VI)
    confirm2 = DecriptwCBC(confirm2,KCBC,VI)
    confirm1 = confirm1.decode("utf-8")
    confirm2 = confirm2.decode("utf-8")
    if confirm1 != 'da' or confirm2 != 'da':
        print("Unul din clienti nu a confirmat. Serverul se inchide")
        client1.send(bytes("NU","utf-8"))
        client2.send(bytes("NU","utf-8"))
        exit()
    client1.send(bytes("start","utf-8"))
    client2.send(bytes("start","utf-8"))
    criptedMsg = client1.recv(4096)
    client2.send(criptedMsg)
    criptedBlocks1 = client1.recv(20)
    criptedBlocks1 = criptedBlocks1.decode("utf-8")
    sentBlocks1 = client1.recv(20)
    sentBlocks1 = sentBlocks1.decode("utf-8")
    decriptedBlocks2 = client2.recv(20)
    decriptedBlocks2 = decriptedBlocks2.decode("utf-8")
    printedBlocks2 = client2.recv(20)
    printedBlocks2 = printedBlocks2.decode("utf-8")
    print ("Blocuri criptate:", criptedBlocks1)
    print ("Blocuri ce vor fi afisate:", printedBlocks2)
    print ("Blocuri criptate care au fost primite:", sentBlocks1)
    print ("Blocuri de decriptat:", decriptedBlocks2)
    if criptedBlocks1 == printedBlocks2 and sentBlocks1 == decriptedBlocks2:
            print("Comunicare desfasurata corect")
    else : print("Comunicare esuata")
    exit()

#Comunicarea in CFB
elif msg.decode("utf-8") == 'CFB':
    print("S-a ales modul CFB")
    client2.send(bytes("CFB", "utf-8"))
    VI = bytes(get_random_string(16), 'utf-8')
    criptedCFBKey = CriptwAES(KCFB, KAES)
    criptedVI = CriptwAES(VI, KAES)
    client1.send(criptedCFBKey)
    client1.send(criptedVI)
    client2.send(criptedCFBKey)
    client2.send(criptedVI)
    confirm1 = client1.recv(64)
    confirm2 = client2.recv(64)
    confirm1 = DecriptwCFB(confirm1, KCFB, VI)
    confirm2 = DecriptwCFB(confirm2, KCFB, VI)
    confirm1 = confirm1.decode("utf-8")
    confirm2 = confirm2.decode("utf-8")
    if confirm1 != 'da' or confirm2 != 'da':
        print("Unul din clienti nu a confirmat. Serverul se inchide")
        client1.send(bytes("NU", "utf-8"))
        client2.send(bytes("NU", "utf-8"))
        exit()
    client1.send(bytes("start", "utf-8"))
    client2.send(bytes("start", "utf-8"))
    criptedMsg = client1.recv(4096)
    client2.send(criptedMsg)
    criptedBlocks1 = client1.recv(20)
    criptedBlocks1 = criptedBlocks1.decode("utf-8")
    sentBlocks1 = client1.recv(20)
    sentBlocks1 = sentBlocks1.decode("utf-8")
    decriptedBlocks2 = client2.recv(20)
    decriptedBlocks2 = decriptedBlocks2.decode("utf-8")
    printedBlocks2 = client2.recv(20)
    printedBlocks2 = printedBlocks2.decode("utf-8")
    print("Blocuri criptate:", criptedBlocks1)
    print("Blocuri ce vor fi afisate:", printedBlocks2)
    print("Blocuri criptate care au fost primite:", sentBlocks1)
    print("Blocuri de decriptat:", decriptedBlocks2)
    if criptedBlocks1 == printedBlocks2 and sentBlocks1 == decriptedBlocks2:
        print("Comunicare desfasurata corect")
    else:
        print("Comunicare esuata")
    exit()

exit()