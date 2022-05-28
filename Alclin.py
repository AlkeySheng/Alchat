# socket
'''****client端****'''

from socket import *
import des
import rsa
import threading
import time



print("当前时间："+time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())))

IV = [0x51, 0xA2, 0x6C, 0x32, 0x11, 0xF1, 0xD4, 0x09]

HOST = 'localhost'
PORT = 5413
BUFF =1024
ADDR = (HOST,PORT)

t = 2

s2 = socket(AF_INET,SOCK_STREAM)
s2.connect(ADDR)

key = '6A4B3C7D9E2F1F3F'

print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))+' start to change key!')
s2.send('changekey'.encode('utf-8'))

modulus = int(s2.recv(BUFF).decode('utf-8'))
exponent = int(s2.recv(BUFF).decode('utf-8'))

print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))+' start to build pubkey')
pubkey = rsa.PublicKey(modulus, exponent)

print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))+' encrypt des-key')
crypto = rsa.encrypt(key.encode('utf8'), pubkey)

print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))+' send encrypted des-key')
s2.send(crypto)

def _SendMessage():
    while True:
        s2_send_data = input(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())) + ' 客户端>>>:')
        s2_send_data = des._DES(s2_send_data, key, IV, 0)
        s2_send_data = s2_send_data.encode('utf-8')
        if len(s2_send_data) > 0:
            s2.send(s2_send_data)
            
def _RecvMessage():
    while True:
        time.sleep(t)
        s2_recv_data = s2.recv(BUFF)
    
        if not s2_recv_data:
            break
   
        s2_recv_data = s2_recv_data.decode()
        print('加密信息：'+s2_recv_data)
        s2_recv_data = des._DES(s2_recv_data, key, IV, 1)
    
        if s2_recv_data == 'quit':
            break 
        print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())) + ' 服务端>>>:' + s2_recv_data)
    
class A(threading.Thread):
        def __init__(self):
            threading.Thread.__init__(self)
    
        def run(self):
            _SendMessage()

a = A()
a.start()
    
while True:
    _RecvMessage()
       
#s2.close()