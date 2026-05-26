from socket import socket
import threading

from Utility.cipher import Cipher


class User:
    def __init__(self, tcp_socket: socket, address, udp_socket: socket):
        self.tcp_socket = tcp_socket
        self.udp_socket = udp_socket
        self.address = address

        self.cipher = None
        self.shared_key = None

        threading.Thread(target=self.handle_tcp,daemon=True).start()

    def perform_handshake(self):
        client_public_key = self.tcp_socket.recv(1024)

        private_key, public_key = Cipher.get_dh_public_key()

        shared_key = Cipher.get_dh_shared_key(
            private_key,
            client_public_key
        )

        self.shared_key = shared_key
        self.cipher = Cipher(shared_key)

        self.tcp_socket.send(public_key)

        print(f"[HANDSHAKE] Connected to {self.address}")

    def handle_tcp(self):
        try:
            self.perform_handshake()

            while True:
                encrypted_packet = self.tcp_socket.recv(1024)

                if not encrypted_packet:
                    print(f"[TCP] Disconnected: {self.address}")
                    break

                decrypted_packet = self.cipher.aes_decrypt(
                    encrypted_packet
                )

                print(
                    f"[TCP] {self.address}: "
                    f"{decrypted_packet}"
                )

        except Exception as error:
            print(f"[TCP ERROR] {self.address}: {error}")

        finally:
            self.disconnect()

    def disconnect(self):
        try:
            self.tcp_socket.close()
        except:
            pass