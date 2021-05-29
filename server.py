#!/usr/bin/env python3
import socket
from itertools import cycle

from noise.connection import NoiseConnection, Keypair

if __name__ == '__main__':
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('localhost', 2000))
    s.listen(1)

    print("waiting for incoming")
    sock, addr = s.accept()
    print('Accepted connection from', addr)

    print("creating protocol")
    noise = NoiseConnection.from_name(b'Noise_XK_25519_ChaChaPoly_SHA256')

    our_static = bytes.fromhex(
        "2121212121212121212121212121212121212121212121212121212121212121")
    print("our private")
    noise.set_keypair_from_private_bytes(Keypair.STATIC, our_static)

    our_ephemeral = bytes.fromhex(
        "2222222222222222222222222222222222222222222222222222222222222222")
    noise.set_keypair_from_private_bytes(Keypair.EPHEMERAL, our_ephemeral)

    their_static = bytes.fromhex(
        "1111111111111111111111111111111111111111111111111111111111111111")
    print("their private")
    noise.set_keypair_from_private_bytes(Keypair.REMOTE_STATIC, their_static)

    print("setting responder")
    noise.set_as_responder()
    print("start handshake")
    noise.start_handshake()

    # Perform handshake. Break when finished
    for action in cycle(['receive', 'send']):
        print("\naction: %s" % action)
        if noise.handshake_finished:
            print("handshake finished")
            break
        elif action == 'send':
            ciphertext = noise.write_message()
            print("handshake send ciphertext: %s" % ciphertext.hex())
            sock.sendall(ciphertext)
            print("done sending")
        elif action == 'receive':
            data = sock.recv(2048)
            print("handshake recv data: %s" % data.hex())
            plaintext = noise.read_message(data)
            print("handshake plaintext: %s" % plaintext.hex())

    # Endless loop "echoing" received data
    while True:
        print("echoing loop")
        data = sock.recv(2048)
        print("recv data: %s" % data.hex())
        if not data:
            print("breaking")
            break
        print("decrypting data")
        received = noise.decrypt(data)
        print("received to send: %s" % received.decode("utf8"))
        msg = received.decode("utf8") + " echoed"
        sock.sendall(noise.encrypt(msg.encode("utf8")))
        print("sent")

