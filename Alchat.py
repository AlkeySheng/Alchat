# socket
'''****server端****'''
from socket import *
import des
import rsa
import threading
import time


print("当前时间："+time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())))

#key = '6A4B3C7D9E2F1F3F'
IV = [0x51, 0xA2, 0x6C, 0x32, 0x11, 0xF1, 0xD4, 0x09]
key = ''

# AF_INET --> IPv4  SOCK_STREAM --> TCP 

HOST = '0.0.0.0'
PORT = 5413
BUFF = 1024
ADDR = (HOST,PORT)

s1 = socket(AF_INET,SOCK_STREAM)
s1.bind(ADDR)
s1.listen(5)
print('sever is running')
print('waiting for connection...')
conn, addr = s1.accept()
print('...connecting from:', addr)


def _SendMessage():
    while True:
        s1_send_data = input(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())) + ' 服务器>>>:')
        s1_send_data = des._DES(s1_send_data, key, IV, 0)
        s1_send_data = s1_send_data.encode('utf-8')
        if len(s1_send_data) > 0:
            conn.send(s1_send_data)

def _RecvMessage():
    while True:
        s1_recv_data = conn.recv(BUFF)
        if not s1_recv_data:
            break
        s1_recv_data = s1_recv_data.decode()
        print('加密信息：'+s1_recv_data)
        s1_recv_data = des._DES(s1_recv_data, key, IV, 1)
        if s1_recv_data == 'quit': 
            break
        print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())) + ' 客户端>>>:' + s1_recv_data)
        
class A(threading.Thread):
        def __init__(self):
            threading.Thread.__init__(self)
    
        def run(self):
            _RecvMessage()


while True:
    if not key:
        s1_recv_data = conn.recv(BUFF)
        
        if s1_recv_data.decode('utf-8') == 'changekey':
            print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))+' start to change key!')
            (pubkey, privkey) = rsa.newkeys(512, poolsize=8)
            print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))+' create pubkey & privkey')
            modulus = pubkey.n
            exponent = pubkey.e
            conn.send(str(modulus).encode('utf-8'))
            conn.send(str(exponent).encode('utf-8'))
            print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))+' send pubkey')
            key = conn.recv(BUFF)
            print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))+' recv encrypted des-key')
            key = rsa.decrypt(key, privkey)
            print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))+' decrypt des-key')
            key = key.decode()
    a = A()  
    a.start()
    _SendMessage()
        
s1.close()