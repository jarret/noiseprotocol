#!/usr/bin/env python3
import socket
from itertools import cycle

from noise.connection import NoiseConnection, Keypair

sock = socket.socket()
sock.connect(('localhost', 2000))

print("creating protocol")
noise = NoiseConnection.from_name(b'Noise_XK_secp256k1_ChaChaPoly_SHA256')

# Set role in this connection as initiator
print("setting initiator")
noise.set_as_initiator()

print("our private")
our_static = bytes.fromhex(
    "1111111111111111111111111111111111111111111111111111111111111111")
noise.set_keypair_from_private_bytes(Keypair.STATIC, our_static)

our_ephemeral = bytes.fromhex(
    "1212121212121212121212121212121212121212121212121212121212121212")
noise.set_keypair_from_private_bytes(Keypair.EPHEMERAL, our_ephemeral)

print("their private")
their_static = bytes.fromhex(
        "2121212121212121212121212121212121212121212121212121212121212121")
noise.set_keypair_from_private_bytes(Keypair.REMOTE_STATIC, their_static)

print("start handshake")
# Enter handshake mode
noise.start_handshake()

# Perform handshake. Break when finished
for action in cycle(['send', 'receive']):
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


# send and receive echo loop
for payload in ["payload one", "payload two", "payload three"]:
    p = payload.encode("utf8")
    print("sending payload: %s" % p)
    encrypted_message = noise.encrypt(p)
    print("encrypted_message sendall: %s" % encrypted_message.hex())
    sock.sendall(encrypted_message)

    ciphertext = sock.recv(2048)
    print("cyphertext recv: %s" % ciphertext.hex())
    plaintext = noise.decrypt(ciphertext).decode("utf8")
    print("got decrypted: %s" % plaintext)
