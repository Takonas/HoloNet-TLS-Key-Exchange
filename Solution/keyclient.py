import socket
import struct
import aesKeyExcGen as AESKeyGen
import rsaKeyExcGen as RSAKeyGen

convertInitSend = lambda mc,rc,sp,un,name:struct.pack('BBBB8s', mc,rc,sp,un,name)
convertInitReceive = lambda x: struct.unpack('BBBBI8s', x)
convertRSASend = lambda mc,rc,sp,un,port,key: struct.pack('BBBBI162B', mc,rc,sp,un,port,*key)
convertRSAReceive = lambda x: struct.unpack('BBBBI162s', x)
convertAESSend = lambda mc,rc,sp,un,port,aes: struct.pack('BBBBI128B', mc,rc,sp,un,port,*aes)
convertAESReceive = lambda x: struct.unpack('BBBBI128s', x)
convertENCSend = lambda mc,rc,sp,un,aes: struct.pack('BBBB32B', mc,rc,sp,un,*aes)
convertENCReceive = lambda x: struct.unpack('BBBB32s', x)


def run_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_ip = "127.0.0.1"
    server_port = 2302
    client.connect((server_ip, server_port))

    msg = convertInitSend(1,0,0,0, "HConnor".rjust(8,"_").encode("utf-8"))
    client.send(msg)
    response = convertRSAReceive(client.recv(1024))
    key = response[5]
    rsakey = RSAKeyGen.RSAKeyGen()
    clientrsakey = RSAKeyGen.RSAKeyGen()
    clientrsakey.loadKey(key)

    msg = convertRSASend(2, 0, 1, 0, 0, rsakey.getPublicKey())
    client.send(msg)
    response = client.recv(1024)
    response = convertAESReceive(response)
    b = rsakey.decrypt(response[5])
    a = struct.unpack('16s64s', b)
    clientrsakey.genHMAC(clientrsakey.getPublicKey()).encode("utf-8")
    clientrsakey.HMACverify(a[1])
    aeskey = AESKeyGen.AESKeyGen(key=a[0])
    client.close()

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server_ip, 2305))

    try:
        data = aeskey.encrypt(aeskey.pad("HConnor".rjust(8,"_").encode("utf-8")))
        msg = convertENCSend(1, 0, 2, 1, data)
        client.send(msg)
        response = convertENCReceive(client.recv(1024))
        d = aeskey.decrypt(response[4])
        print(d)


    except Exception as e:
        print(f"Error: {e}")
    finally:
        # close client socket (connection to the server)
        client.close()
        print("Connection to server closed")


run_client()