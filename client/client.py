import socket
import json
import os
import hashlib
import random
import logging
#import rsa

escape_dict = {'\a': r'\a',
               '\b': r'\b',
               '\c': r'\c',
               '\f': r'\f',
               '\n': r'\n',
               '\r': r'\r',
               '\t': r'\t',
               '\v': r'\v',
               '\0': r'\0',
               '\1': r'\1',
               '\2': r'\2',
               '\3': r'\3',
               '\4': r'\4',
               '\5': r'\5',
               '\6': r'\6',
               '\7': r'\7',
               '\8': r'\8',
               '\9': r'\9'}


_random = random.SystemRandom()

logging.basicConfig(format='[%(asctime)s] %(filename)s:%(lineno)d %(levelname)s %(message)s', level=logging.DEBUG)

logger = logging.getLogger()

def raw(text):
    """Returns a raw string representation of text"""
    new_string = ''
    for char in text:
        try:
            new_string += escape_dict[char]
        except KeyError:
            new_string += char
    return new_string


def get_random_int():
    return _random.randint(10000000, 99999999)

def debug(s):
    logging.debug(s)
    
class BaseClient(object):

    def __init__(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self, remote):
        self._socket.connect(remote)

    def read(self, sz, conn=None):
        if conn is None:
            conn = self._socket
        return conn.recv(sz)

    def write(self, buffer, conn=None):
        if conn is None:
            conn = self._socket
        conn.sendall(str(buffer))

    def close(self, conn=None):
        if conn is None:
            conn = self._socket
        conn.close()


class CustomSSLClient(BaseClient):

    def __init__(self):
        super(CustomSSLClient, self).__init__()

        self.random1 = get_random_int()
        self.server_random = None
        self.private_key = None
        self.public_key = None

        self.ms = None

        self.server_pubkey = None
        self.server_random = None

        #(self.public_key, self.private_key) = rsa.newkeys(2048)
        #debug(self.public_key, self.private_key)

    def handshake(self):
        if not self.server_hello():
            debug("hello to server failed")
            return False
        data = self.read(1024)
        if not self.process_server_hello(data):
            debug("hello from error")
            return False
        self.send_ack()
        if not self.process_server_finish(self.read(1024)):
            debug("error when processing server fin message")
            return False
        return True

    def read_key_from_file(self):
        with open("private.pem", 'r') as f:
            self.private_key = f.read()

        with open("public.pem", 'r') as f:
            self.public_key = f.read()
            
    def generate_key(self):
        if os.path.exists("private.pem") and os.path.exists("public.pem"):
            self.read_key_from_file()
        else:
            os.system("openssl genrsa -out private.pem 2048")
            os.system(
                "openssl rsa -in private.pem -outform PEM -pubout -out public.pem")
            self.read_key_from_file()

    def server_hello(self):
        msg_dict = {"magic": self.random1, "type": "HELO"}
        try:
            self.write(json.dumps(msg_dict))
        except Exception:
            return False

        return True

    def process_server_hello(self, msg):
        try:
            d = json.loads(raw(msg))
        except KeyError:
            return False

        s = "\"body\":{\"pubkey\":\"" + d['body']['pubkey'].encode(
            'ascii', 'ignore') + "\",\"magic\":" + str(d['body']['magic']) + "}"
        ck = self.md5(s)

        if ck != d['checksum']:
            # error
            debug("checksum error")
            return False
        else:
            self.server_pubkey = d['body']['pubkey'].encode('ascii', 'ignore')
            self.server_random = d['body']['magic']
            return True

    def send_ack(self):
        msg_dict = {"type": "ACK"}

        blocks = len(self.public_key) / 128
        enc = []
        for i in range(0, blocks):
            enc.append(
                self.encrypt(self.public_key[128 * i: 128 * (i + 1)], self.server_pubkey))
        enc.append(
            self.encrypt(self.public_key[blocks * 128:], self.server_pubkey))

        msg_dict['epk'] = [map(ord, i) for i in enc]
        msg_dict['length'] = len(self.public_key)
        msg_dict['checksum'] = self.md5(self.public_key)

        self.write(json.dumps(msg_dict))

    def md5(self, str):
        m = hashlib.md5()
        m.update(str)
        return m.hexdigest()

    def encrypt(self, msg, key=None):
        if key:
            with open("tempkey.pem", 'w') as f:
                f.write(key)

        with open("tempfile.txt", 'w') as f:
            f.write(msg)

        if not key:
            os.system(
                "openssl rsautl -in tempfile.txt -out temp.rsa -encrypt -pubin -inkey public.pem")
        else:
            os.system(
                "openssl rsautl -in tempfile.txt -out temp.rsa -encrypt -pubin -inkey tempkey.pem")

        r = ""
        with open("temp.rsa", 'r') as f:
            r = f.read()

        os.remove("tempfile.txt")
        os.remove("temp.rsa")
        if key:
            os.remove("tempkey.pem")

        return r

    def process_server_finish(self, msg):
        d = json.loads(raw(msg))
        crs = str(self.server_random) + str(self.random1) + \
            self.server_pubkey + self.public_key
        cms = self.md5(crs)

        if d['ms'] == cms:
            self.ms = cms
            return True
        return False

    def ssl_read_from_server(self):
        return self.ssl_read(self._socket, self.ms)

    def ssl_write_to_server(self, msg):
        self.ssl_write(self._socket, msg, self.ms)
        
    def ssl_read(self, conn, key):
        data = self.read(1024, conn)
        with open("enc.txt", "w+") as f:
            f.write(data)

        os.system("openssl enc -aes-128-cbc -d -in enc.txt -out data.txt -K "
                  + key + " -iv 0123456789")
        with open("data.txt", "r") as f:
            return f.read()

    def ssl_write(self, conn, msg, key):
        with open("msg.txt", 'w+') as f:
            f.write(msg)

        os.system("openssl enc -aes-128-cbc -in msg.txt -out enc_msg.txt -K " +
                  key + " -iv 0123456789")

        with open("enc_msg.txt", 'r') as f:
            self.write(f.read(), conn)



class ImageNode(CustomSSLClient):

    def __init__(self, addr, port):
        super(ImageNode, self).__init__()
        self.addr = addr
        self.port = port
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    def listen(self, backlog=1):
        self.listen_socket.listen(backlog)

    def add_image(self, image_filename):
        f = open(filename, 'rb')
        t = f.read()
        _md5 = self.md5(t)
        d = {'type': 'ADD',
             'filename': image_filename, 
             'checksum': _md5
            }
        self.ssl_write_to_server(json.dumps(d))

    def query_image(self, image_filename):
        d = {'type': 'QUERY',
             'filename': image_filename
            }
        self.ssl_write_to_server(json.dumps(d))


if __name__ == '__main__':
    client = ImageNode('127.0.0.1', 8090)
    client.generate_key()
    client.connect(('127.0.0.1', 19910))
    debug("try to establish security connection...")
    if client.handshake():
        debug("handshake ok.")
    
    while True:
        data = raw_input("Input message: ")
        if data == 'QUERY':
            client.query_image("HelloWorld.png")
        else:
            client.ssl_write_to_server(data)
            debug("write to server: " + data)
        recv = client.ssl_read_from_server()
        debug("receive from server: " + recv)
