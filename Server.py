import socket
import threading

import Constants
import Networking.Saved
from Networking.User import User


server_tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def broadcast(data: bytes, sender: User):
    for user in Networking.Saved.Users:
        if user is sender:
            continue

        if user.address == sender.address:
            continue

        if user.cipher is None or user.udp_address is None:
            continue

        try:
            encrypted = user.cipher.aes_encrypt(data)
            server_udp_socket.sendto(encrypted, user.udp_address)

        except Exception as e:
            print(f"[UDP SEND ERROR] {e}")


def handle_udp():
    while True:
        try:
            packet, address = server_udp_socket.recvfrom(Constants.MAX_PACKET_SIZE)

            sender = None
            for user in Networking.Saved.Users:
                if user.address[0] == address[0]:
                    sender = user
                    break

            if sender is None or sender.cipher is None:
                continue

            decrypted = sender.cipher.aes_decrypt(packet)

            if sender.udp_address is None:
                sender.udp_address = address
                print(f"[UDP] Registered {sender.address} -> {address}")

            broadcast(decrypted, sender)

        except Exception as e:
            print(f"[UDP LOOP ERROR] {e}")


def handle_tcp_client(client_socket, address):
    user = User(client_socket, address, server_udp_socket)
    Networking.Saved.Users.append(user)
    print(f"[TCP] User connected: {address}")


def start_server():
    print("Server starting...")

    server_tcp_socket.bind(("0.0.0.0", Constants.TCP_PORT))
    server_tcp_socket.listen(100)

    server_udp_socket.bind(("0.0.0.0", Constants.UDP_PORT))

    threading.Thread(target=handle_udp, daemon=True).start()

    while True:
        client_socket, address = server_tcp_socket.accept()
        handle_tcp_client(client_socket, address)


if __name__ == "__main__":
    start_server()