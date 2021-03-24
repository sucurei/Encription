import socket
from Crypto.Cipher import AES
from Crypto.Util import Padding

#Functie XOR
def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

KAES = b"1234567890123456"

#Criptare cu AES
def CriptwAES(text, key):
    cipher = AES.new(key,AES.MODE_ECB)
    cript = cipher.encrypt(Padding.pad(text,16,'pkcs7'))
    return cript

#Decriptare cu AES
def DecriptwAES(text, key):
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

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((socket.gethostname(),1234))

msg = s.recv(254)

#aici este implementarea pentru A(primul client)
if len(msg.decode("utf-8")) == 104:
    print(msg.decode("utf-8"))
    print("Veti fi anuntati cand este posibila comunicarea.")
    msg = s.recv(8)
    print("Celalalt client s-a conectat la server. Puteti comunica.")
    print("Alegeti un mod de operare:\n1.CBC\n2.CFB")
    mod = input()
    while mod != "CBC" and mod != "CFB":
        print("Nu ati ales un mod de operare corect. Mai incercati o data.")
        mod = input()

    #CBC pentru A (primul client)
    if mod == "CBC":
        s.send(bytes(mod,"utf-8"))
        criptedKey = s.recv(128)
        Key = DecriptwAES(criptedKey,KAES)
        criptedVI = s.recv(128)
        VI = DecriptwAES(criptedVI,KAES)
        print("Scrieti da pentru a confirma. Orice alt text va duce la neconfirmare.")
        ok = 0
        confirm = input()
        if confirm == 'da':
            ok = 1
        confirm = confirm.encode("utf-8")
        confirm = CriptwCBC(confirm,Key,VI)
        s.send(confirm)
        if ok == 0:
            exit()
        con = s.recv(8).decode("utf-8")
        if con == "NU":
            print("Celalalt client nu a confirmat.")
            exit()
        file = open("mesaj.txt","r")
        file_content = file.read()
        file_content = bytes(file_content,"utf-8")
        criptedMsg = CriptwCBC(file_content, Key, VI)
        criptedBlocks = int(len(file_content) / 16)
        if len(file_content) % 16 != 0:
            criptedBlocks = criptedBlocks + 1
        sentBlocks = int(len(criptedMsg) / 16)
        if len(criptedMsg) % 16 != 0:
            sentBlocks = sentBlocks + 1
        s.send(criptedMsg)
        print ("Au fost criptate", criptedBlocks, "blocuri")
        print ("Au fost trimise", sentBlocks, "blocuri")
        s.send(bytes(str(criptedBlocks),"utf-8"))
        s.send(bytes(str(sentBlocks),"utf-8"))
        exit()

    # CFB pentru A (primul client)
    if mod == "CFB":
        s.send(bytes(mod, "utf-8"))
        criptedKey = s.recv(128)
        Key = DecriptwAES(criptedKey, KAES)
        criptedVI = s.recv(128)
        VI = DecriptwAES(criptedVI, KAES)
        print("Scrieti da pentru a confirma. Orice alt text va duce la neconfirmare.")
        ok = 0
        confirm = input()
        if confirm == 'da':
            ok = 1
        confirm = confirm.encode("utf-8")
        confirm = CriptwCFB(confirm, Key, VI)
        s.send(confirm)
        if ok == 0:
            exit()
        con = s.recv(8).decode("utf-8")
        if con == "NU":
            print("Celalalt client nu a confirmat.")
            exit()
        file = open("mesaj.txt", "r")
        file_content = file.read()
        file_content = bytes(file_content, "utf-8")
        criptedMsg = CriptwCFB(file_content, Key, VI)
        criptedBlocks = int(len(file_content) / 16)
        if len(file_content) % 16 != 0:
            criptedBlocks = criptedBlocks + 1
        sentBlocks = int(len(criptedMsg) / 16)
        if len(criptedMsg) % 16 != 0:
            sentBlocks = sentBlocks + 1
        s.send(criptedMsg)
        print("Au fost criptate", criptedBlocks, "blocuri")
        print("Au fost trimise", sentBlocks, "blocuri")
        s.send(bytes(str(criptedBlocks), "utf-8"))
        s.send(bytes(str(sentBlocks), "utf-8"))
        exit()

#aici este implementarea pentru B(al doilea client)
elif len(msg.decode("utf-8")) == 78:
    print(msg.decode("utf-8"))
    mod = s.recv(4)
    mod = mod.decode("utf-8")

    # CBC pentru B (al doilea client)
    if mod == "CBC":
        print("S-a ales comunicarea prin CBC.")
        criptedKey = s.recv(128)
        Key = DecriptwAES(criptedKey, KAES)
        criptedVI = s.recv(128)
        VI = DecriptwAES(criptedVI, KAES)
        print("Scrieti da pentru a confirma. Orice alt text va duce la neconfirmare.")
        ok = 0
        confirm = input()
        if confirm == 'da':
            ok = 1
        confirm = confirm.encode("utf-8")
        confirm = CriptwCBC(confirm, Key, VI)
        s.send(confirm)
        if ok == 0:
            exit()
        con = s.recv(8).decode("utf-8")
        if con == "NU":
            print("Celalalt client nu a confirmat.")
            exit()
        criptedMsg = s.recv(1024)
        Msg = DecriptwCBC(criptedMsg, Key, VI)
        decriptedBlocks = int(len(criptedMsg) / 16)
        if len(criptedMsg) % 16 != 0:
            decriptedBlocks = decriptedBlocks + 1
        printedBlocks = int(len(Msg) / 16)
        if len(Msg) % 16 != 0:
            printedBlocks = printedBlocks + 1
        print("Au fost decriptate", decriptedBlocks, "blocuri")
        print("Au fost printate", printedBlocks, "blocuri")
        print("Mesajul de la clientul A:")
        print(Msg.decode("utf-8"))
        s.send(bytes(str(decriptedBlocks),"utf-8"))
        s.send(bytes(str(printedBlocks),"utf-8"))
        exit()

    # CFB pentru B (al doilea client)
    if mod == "CFB":
        print("S-a ales comunicarea prin CFB.")
        criptedKey = s.recv(128)
        Key = DecriptwAES(criptedKey, KAES)
        criptedVI = s.recv(128)
        VI = DecriptwAES(criptedVI, KAES)
        print("Scrieti da pentru a confirma. Orice alt text va duce la neconfirmare.")
        ok = 0
        confirm = input()
        if confirm == 'da':
            ok = 1
        confirm = confirm.encode("utf-8")
        confirm = CriptwCFB(confirm, Key, VI)
        s.send(confirm)
        if ok == 0:
            exit()
        con = s.recv(8).decode("utf-8")
        if con == "NU":
            print("Celalalt client nu a confirmat.")
            exit()
        criptedMsg = s.recv(1024)
        Msg = DecriptwCFB(criptedMsg, Key, VI)
        decriptedBlocks = int(len(criptedMsg) / 16)
        if len(criptedMsg) % 16 != 0:
            decriptedBlocks = decriptedBlocks + 1
        printedBlocks = int(len(Msg) / 16)
        if len(Msg) % 16 != 0:
            printedBlocks = printedBlocks + 1
        print("Au fost decriptate", decriptedBlocks, "blocuri")
        print("Au fost printate", printedBlocks, "blocuri")
        print("Mesajul de la clientul A:")
        print(Msg.decode("utf-8"))
        s.send(bytes(str(decriptedBlocks), "utf-8"))
        s.send(bytes(str(printedBlocks), "utf-8"))
        exit()

exit()