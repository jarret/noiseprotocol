from cryptography.hazmat.primitives.asymmetric import x25519, x448
from cryptography.hazmat.primitives import serialization

from noise.backends.default.keypairs import KeyPair25519, KeyPair448, KeyPairSecp256k1
from noise.exceptions import NoiseValueError
from noise.functions.dh import DH

import secp256k1


class ED25519(DH):
    @property
    def klass(self):
        return KeyPair25519

    @property
    def dhlen(self):
        return 32

    def generate_keypair(self) -> 'KeyPair':
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return KeyPair25519(private_key, public_key,
                            public_key.public_bytes(serialization.Encoding.Raw,
                                                    serialization.PublicFormat.Raw))

    def dh(self, private_key, public_key) -> bytes:
        if not isinstance(private_key, x25519.X25519PrivateKey) or not isinstance(public_key, x25519.X25519PublicKey):
            raise NoiseValueError('Invalid keys! Must be x25519.X25519PrivateKey and x25519.X25519PublicKey instances')
        return private_key.exchange(public_key)


class ED448(DH):
    @property
    def klass(self):
        return KeyPair448

    @property
    def dhlen(self):
        return 56

    def generate_keypair(self) -> 'KeyPair':
        private_key = x448.X448PrivateKey.generate()
        public_key = private_key.public_key()
        return KeyPair448(private_key, public_key,
                          public_key.public_bytes(serialization.Encoding.Raw,
                                                  serialization.PublicFormat.Raw))

    def dh(self, private_key, public_key) -> bytes:
        if not isinstance(private_key, x448.X448PrivateKey) or not isinstance(public_key, x448.X448PublicKey):
            raise NoiseValueError('Invalid keys! Must be x448.X448PrivateKey and x448.X448PublicKey instances')
        return private_key.exchange(public_key)


class Secp256k1(DH):
    @property
    def klass(self):
        return KeyPairSecp256k1

    @property
    def dhlen(self):
        return 33

    def generate_keypair(self) -> 'KeyPair':
        private_key = secp256k1.PrivateKey()
        public_key = private_key.pubkey
        #private_key = x25519.X25519PrivateKey.generate()
        #public_key = private_key.public_key()
        return KeyPair25519(private_key, public_key,
                            public_key.public_bytes(serialization.Encoding.Raw,
                                                    serialization.PublicFormat.Raw))

    def dh(self, private_key, public_key) -> bytes:
        if not isinstance(private_key, secp256k1.PrivateKey) or not isinstance(public_key, secp256k1.PublicKey):
            raise NoiseValueError('Invalid keys! Must be secp256k1.PrivateKey and secp256k1.PublicKey instances')
        private_bytes = private_key.private_key
        print("dh private bytes: %s len: %d" % (private_bytes.hex(),
                                                len(private_bytes)))
        print("dh public bytes: %s len: %d" % (public_key.serialize().hex(),
                                               len(public_key.serialize())))
        ss_bytes = public_key.ecdh(private_bytes)
        print("ss_bytes: %s len: %d" % (ss_bytes.hex(), len(ss_bytes)))
        return ss_bytes
        #return private_key.exchange(public_key)
