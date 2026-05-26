from socket import socket
import threading

from Utility.cipher import Cipher

class User:
    def __init__(self, tcpClient: socket, address, udpSocket):

        self.TcpClient = tcpClient
        self.Address = address

        self.UdpSocket = udpSocket

        self.UdpAddr = None

        self.Cipher = None
        self.Diff = None
        self.PublicKey = None

        threading.Thread(
            target=self.handleTCP,
            daemon=True
        ).start()

    def handleTCP(self):
        try:

            clientKey = self.TcpClient.recv(1024)

            diff, publicKey = Cipher.get_dh_public_key()

            sharedKey = Cipher.get_dh_shared_key(diff,clientKey)

            self.Cipher = Cipher(sharedKey)

            self.Diff = diff
            self.PublicKey = publicKey

            self.TcpClient.send(publicKey)

            print(f"Handshake complete: {self.Address}")

            while True:

                packet = self.TcpClient.recv(1024)

                if not packet:
                    print(f"TCP disconnected: {self.Address}")
                    break

                decrypted = self.Cipher.aes_decrypt(packet)

                print("TCP:", decrypted)

        except Exception as e:
            print("TCP ERROR:", e)