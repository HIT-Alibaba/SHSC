import socket
import json
import os
import hashlib

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


def raw(text):
    """Returns a raw string representation of text"""
    new_string = ''
    for char in text:
        try:
            new_string += escape_dict[char]
        except KeyError:
            new_string += char
    return new_string


class BaseClient(object):

    def __init__(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self, remote):
        self._socket.connect(remote)

    def read(self, sz):
        return self._socket.recv(sz)

    def write(self, buffer):
        self._socket.sendall(str(buffer))

    def close(self):
        self._socket.close()


class CustomSSLClient(BaseClient):

    def __init__(self):
        super(CustomSSLClient, self).__init__()

        self.random1 = 1234567890
        self.private_key = None
        self.public_key = None

        self.server_pubkey = None
        self.server_random = None

        #(self.public_key, self.private_key) = rsa.newkeys(2048)
        #print(self.public_key, self.private_key)

    def generate_key(self):
        os.system("openssl genrsa -out private.pem 2048")
        os.system("openssl rsa -in private.pem -outform PEM -pubout -out public.pem")

        with open("private.pem", 'r') as f:
            self.private_key = f.read()

        with open("public.pem", 'r') as f:
            self.public_key = f.read()

    def server_hello(self):
        msg_dict = {"magic": self.random1, "type": "HELO"}
        self.write(json.dumps(msg_dict))
        data = self.read(1024)
        self.process_server_hello(data)

    def process_server_hello(self, msg):
        d = json.loads(raw(msg))

        s = "\"body\":{\"pubkey\":\"" + d['body']['pubkey'].encode(
            'ascii', 'ignore') + "\",\"magic\":" + str(d['body']['magic']) + "}"
        ck = self.md5(s)

        if ck != d['checksum']:
            # error
            print("checksum error")
        else:
            self.server_pubkey = d['body']['pubkey'].encode('ascii', 'ignore')
            self.server_random = d['body']['magic']
            self.send_ack()

    def send_ack(self):
        msg_dict = {"type":"ACK"}

        blocks = len(self.public_key) / 128
        enc = []
        for i in range(0, blocks):
            enc.append(self.encrypt(self.public_key[128*i: 128*(i+1)], self.server_pubkey))
        enc.append(self.encrypt(self.public_key[blocks*128:], self.server_pubkey))

        msg_dict['epk'] = [map(ord, i) for i in enc]
        msg_dict['length'] = len(self.public_key)
        msg_dict['checksum'] = self.md5(self.public_key)

        self.write(json.dumps(msg_dict))
        print(self.read(1024))

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
            os.system("openssl rsautl -in tempfile.txt -out temp.rsa -encrypt -pubin -inkey public.pem")
        else:
            os.system("openssl rsautl -in tempfile.txt -out temp.rsa -encrypt -pubin -inkey tempkey.pem")

        r = ""
        with open("temp.rsa", 'r') as f:
            r = f.read()

        os.remove("tempfile.txt")
        os.remove("temp.rsa")
        if key:
            os.remove("tempkey.pem")

        return r


if __name__ == '__main__':
    client = CustomSSLClient()
    client.generate_key()
    client.connect(('127.0.0.1', 19910))
    client.server_hello()
