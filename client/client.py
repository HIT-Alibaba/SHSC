import socket
import json

class BaseClient(object):
    def __init__(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


    def connect(self, remote):
        self._socket.connect(remote)

    def read(self):
        return self._socket.recv()

    def write(self, buffer):
        self._socket.sendall(str(buffer))

    def close(self):
        self._socket.close()


class CustomSSLClient(BaseClient):
    def __init__(self):
        super(CustomSSLClient, self).__init__()

        self.random1 = 1234567890

    def hello(self):
        msg_dict = {"magic": self.random1, "type": "HELO"}
        self.write(json.dumps(msg_dict))

    def process_server_hello(self, msg):
        pass

    def send_ack(self):
        pass

if __name__ == '__main__':
    client = CustomSSLClient()
    client.connect(('127.0.0.1', '8888'))
    client.hello()
