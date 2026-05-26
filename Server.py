import socket
import threading
import Networking.Global
from Networking.User import User

TCP_PORT = 3683
UDP_PORT = 5682

ServerTCPSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ServerUDPSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def handleUDP():
    while True:
        try:
            packet, addr = ServerUDPSocket.recvfrom(65507)
            sender = None

            for user in Networking.Global.Users:
                if user.UdpAddr == addr:
                    sender = user
                    break

            if sender is None:
                for user in Networking.Global.Users:
                    if user.UdpAddr is None:
                        user.UdpAddr = addr
                        sender = user

                        print(f"UDP registered: {addr} for {user.Address}")
                        break

            if sender is None:
                continue

            if sender.Cipher is None:
                continue

            decrypted = sender.Cipher.aes_decrypt(packet)

            for user in Networking.Global.Users:
                if user.UdpAddr == sender.UdpAddr:
                    continue

                if user.UdpAddr is None:
                    continue

                if user.Cipher is None:
                    continue

                try:
                    encrypted = user.Cipher.aes_encrypt(decrypted)

                    ServerUDPSocket.sendto(encrypted,user.UdpAddr)

                except Exception as e:
                    print("Send error:", e)

        except Exception as e:
            print("UDP LOOP ERROR:", e)


def init():
    print("Server starting...")

    ServerTCPSocket.bind(("0.0.0.0", TCP_PORT))
    ServerTCPSocket.listen(100)

    ServerUDPSocket.bind(("0.0.0.0", UDP_PORT))

    threading.Thread(target=handleUDP, daemon=True).start()

    while True:
        client, addr = ServerTCPSocket.accept()

        user = User(client,addr,ServerUDPSocket)

        Networking.Global.Users.append(user)

        print(f"User connected: {addr}")


init()