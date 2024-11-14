import socket
import threading
import time
import aesKeyExcGen as AESKeyGen
import rsaKeyExcGen as RSAKeyGen
import struct
import codes
import os
import random
import re

convertInitSend = lambda mc,rc,sp,un,name:struct.pack('BBBB8s', mc,rc,sp,un,name)
convertInitReceive = lambda x: struct.unpack('BBBB8s', x)
convertRSASend = lambda mc,rc,sp,un,port,key: struct.pack('BBBBI162B', mc,rc,sp,un,port,*key)
convertRSAReceive = lambda x: struct.unpack('BBBBI162s', x)
convertAESSend = lambda mc,rc,sp,un,port,aes: struct.pack('BBBBI128B', mc,rc,sp,un,port,*aes)
convertAESReceive = lambda x: struct.unpack('BBBBI128s', x)
convertENCSend = lambda mc,rc,sp,un,aes: struct.pack('BBBB32B', mc,rc,sp,un,*aes)
convertENCReceive = lambda x: struct.unpack('BBBB32s', x)


def handleRC(error):
    match error:
        case codes.RC_INVALID_LENGTH:
            return "INVALID LENGTH"
        case codes.RC_UNKNOWN_FORMAT:
            return "UNKNOWN FORMAT"
        case codes.RC_BAD_KEY:
            return "BAD KEY"
        case _:
            return "UNKNOWN, CONTACT ADMINISTRATOR"


def keyexc(client_socket, addr):
    try:
        client_socket.settimeout(10)
        while True:
            request = client_socket.recv(1024)
            if len(request) == 0:
                break

            # inititalizes key exchange on port by sending back rsa key after user sends name
            if request[0] is codes.MC_INITIATE:
                init = convertInitReceive(request)
                if init[1] is not codes.RC_SUCCESS:
                    print(f"Error in Response Code from Client: {handleRC(request[1])}")
                    break
                if init[2] is not codes.SP_NONE:
                    print("Improper Security Posture Flag from Client, SP_FLAG should be: " + codes.SP_NONE)
                    break
                if not 0 <= init[3] <= 1:
                    print("Improper Mystery Flag from Client, Values can be 0 or 1")
                    break
                client_socket.send(convertRSASend(
                    codes.MC_RESPONSE_INITIATE,
                    codes.RC_SUCCESS,
                    codes.SP_NONE,
                    init[3],
                    2302,
                    rsakey.getPublicKey()))

            # checks if the user is attempting to conduct an AES exchange with a given RSA key
            # will use RSA key given to it by user for transferring AES key
            elif request[0] is codes.MC_EXCHANGE:
                exch = convertRSAReceive(request)
                if exch[1] is not codes.RC_SUCCESS:
                    print(f"Error in Response Code from Client: {handleRC(exch[1])}")
                    break
                if exch[2] is not codes.SP_RSA:
                    print("Improper Security Posture Flag from Client, SP_FLAG should be: " + codes.SP_RSA)
                    break
                if not 0 <= exch[3] <= 1:
                    print("Improper Mystery Flag from Client, Values can be 0 or 1")
                    break
                clientrsakey = RSAKeyGen.RSAKeyGen()
                clientrsakey.loadKey(exch[5])
                mac = rsakey.genHMAC(rsakey.getPublicKey()).encode("utf-8")
                ciphertext = clientrsakey.encrypt(aeskey.getKey() + mac)
                client_socket.send(convertAESSend(
                    codes.MC_RESPONSE_EXCHANGE,
                    codes.RC_SUCCESS,
                    codes.SP_RSA,
                    codes.UN_FALSE,
                    2305,
                    ciphertext
                ))
            elif request[0] is codes.MC_CONNECTION_END:
                print("Message End Request has been received.")
                break
            else:
                print("Unknown Message Code from Client, Valid Options are: " + codes.MC_INITIATE + " or " + codes.MC_EXCHANGE)
            print(f"Received: {request}")
    except Exception as e:
        print(f"EXCEPTION: {e}")
    finally:
        client_socket.close()
        print(f"Connection to ({addr[0]}:{addr[1]}) closed")

# Takes in AES encrypted message and sends it to the HoloNet,
# and clients are sent back a receipt
def flagexc(client_socket, addr):
    try:
        client_socket.settimeout(10)
        while True:
            request = client_socket.recv(1024)
            if request[0] is codes.MC_INITIATE:
                init = convertENCReceive(request)
                if init[1] is not codes.RC_SUCCESS:
                    print(f"Error in Response Code from Client: {handleRC(request[1])}")
                    break
                if init[2] is not codes.SP_AES:
                    print("Improper Security Posture Flag from Client, SP_FLAG should be: " + codes.SP_AES)
                    break
                if not 0 <= init[3] <= 1:
                    print("Improper Mystery Flag from Client, Values can be 0 or 1")
                    break
                name = aeskey.unpad(aeskey.decrypt(init[4])).decode("utf-8")
                flag = genFlag(name)
                msg = flag.encode('utf-8')
                msg = aeskey.encrypt(msg)
                writeFlag(addr, flag, name, init[4])
                client_socket.send(convertENCSend(
                    codes.MC_RESPONSE_INITIATE,
                    codes.RC_SUCCESS,
                    codes.SP_NONE,
                    codes.UN_FALSE,
                    msg))
            print(f"Received: {request}")
            response = "accepted"
            client_socket.send(response.encode('ascii', 'backslashreplace'))
    except Exception as e:
        print(f"EXCEPTION: {e}")
    finally:
        client_socket.close()
        print(f"Connection to ({addr[0]}:{addr[1]}) closed")


# generates a global aeskey used by the holonet every [delay] seconds to avoid
# allowing rebels access to the Imperial HoloNet
def genKeys(delay):
    global aeskey, rsakey
    while True:
        rsakey = RSAKeyGen.RSAKeyGen()
        aeskey = AESKeyGen.AESKeyGen()
        time.sleep(delay)


# flag generation function, we have no idea how this functions internally
# so we used a stand in of 32 bytes of test repeated 8 times
def genFlag(name):
    return "test"*8


# Writes the flag to a local directory of 'keys', new files generated
# based off the name with a max length of 8 characters
def writeFlag(addr, flag, name, encname):
    pwd = os.getcwd()
    if not os.path.exists(pwd + "\\keys"):
        os.mkdir(pwd + "\\keys")
    pwd = os.path.join(pwd,"keys")
    name = re.sub(r'^_*', "", name)
    filename = f"{name}.txt"
    with open(os.path.join(pwd,filename), "w") as file:
        file.write(name)
        file.write("\n"+addr[0])
        file.write("\n"+str(addr[1]))
        file.write("\n"+flag)
        file.write("\n"+encname.hex())
        file.write("\n"+aeskey.getKey().hex())

# Thread-dependent start_server section, will open a thread for the
# keyexc or flagexc depending on the port that is to be used
def start_server(port):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("", port))
        server.listen()
        print(f"Listening on {port}\n")

        if port == 2302:
            while True:
                client_socket, addr = server.accept()
                print(f"Accepted {port} connection from {addr[0]}:{addr[1]}")
                thread1 = threading.Thread(target=keyexc, args=(client_socket, addr,))
                thread1.start()
        if port == 2305:
            while True:
                client_socket, addr = server.accept()
                print(f"Accepted {port} connection from {addr[0]}:{addr[1]}")
                thread2 = threading.Thread(target=flagexc, args=(client_socket, addr,))
                thread2.start()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        server.close()

# Starts the server with a preset delay for AES key generation and
# a thread for the key exchange port and the HoloNet port
def run_server():
    ports = [2302, 2305]
    threads = []
    delay = 30

    thread = threading.Thread(target=genKeys,args=(delay,))
    thread.start()
    threads.append(thread)

    for port in ports:
        thread = threading.Thread(target=start_server, args=(port,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()


run_server()
