import socket
from itertools import cycle

from noise.connection import NoiseConnection, Keypair

sock = socket.socket()
sock.connect(('localhost', 2000))

# Create instance of NoiseConnection, set up to use NN handshake pattern,
# Curve25519 for elliptic curve keypair, ChaCha20Poly1305 as cipher function
# and SHA256 for hashing.
print("creating protocol")
noise = NoiseConnection.from_name(b'Noise_XK_25519_ChaChaPoly_SHA256')

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


print("1 handshake finished: %s" % noise.handshake_finished)




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



# Perform handshake - as we are the initiator, we need to generate first
# message.  We don't provide any payload (although we could, but it would be
# cleartext for this pattern).
#print("write message from proto?")
#message = noise.write_message()

#print("2 handshake finished: %s" % noise.handshake_finished)
# Send the message to the responder - you may simply use sockets or any other
# way to exchange bytes between communicating parties. 
#print("sendall message: %s" % message.hex())
#sock.sendall(message)
# Receive the message from the responder 
#received = sock.recv(2048)
#print("received: %s" % received.hex())
# Feed the received message into noise
#payload = noise.read_message(received)

#print("3 handshake finished: %s" % noise.handshake_finished)

#print("payload: %s" % payload)

# As of now, the handshake should be finished (as we are using NN pattern). 
# Any further calls to write_message or read_message would raise
# NoiseHandshakeError exception.
# We can use encrypt/decrypt methods of NoiseConnection now for encryption and
# decryption of messages.
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
