from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519, x448

from noise.exceptions import NoiseValueError
from noise.functions.keypair import KeyPair

import secp256k1


class KeyPair25519(KeyPair):
    @classmethod
    def from_private_bytes(cls, private_bytes):
        if len(private_bytes) != 32:
            raise NoiseValueError('Invalid length of private_bytes! Should be 32')
        private = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
        public = private.public_key()
        public_bytes = public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        print("keypair private: %s" % private_bytes.hex())
        print("keypair derived public_bytes: %s" % public_bytes.hex())
        return cls(private=private, public=public, public_bytes=public_bytes)

    @classmethod
    def from_public_bytes(cls, public_bytes):
        if len(public_bytes) != 32:
            raise NoiseValueError('Invalid length of public_bytes! Should be 32')
        public = x25519.X25519PublicKey.from_public_bytes(public_bytes)
        pb = public_bytes=public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        print("keypair public_bytes: %s" % pb.hex())
        return cls(public=public, public_bytes=pb)


class KeyPair448(KeyPair):
    @classmethod
    def from_private_bytes(cls, private_bytes):
        if len(private_bytes) != 56:
            raise NoiseValueError('Invalid length of private_bytes! Should be 56')
        private = x448.X448PrivateKey.from_private_bytes(private_bytes)
        public = private.public_key()
        return cls(private=private, public=public, public_bytes=public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))

    @classmethod
    def from_public_bytes(cls, public_bytes):
        if len(public_bytes) != 56:
            raise NoiseValueError('Invalid length of private_bytes! Should be 56')
        public = x448.X448PublicKey.from_public_bytes(public_bytes)
        return cls(public=public, public_bytes=public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))


class KeyPairSecp256k1(KeyPair):
    @classmethod
    def from_private_bytes(cls, private_bytes):
        print("private bytes: %s len: %d" % (private_bytes.hex(),
                                             len(private_bytes)))
        if len(private_bytes) != 32:
            raise NoiseValueError('Invalid length of private_bytes! '
                                  'Should be 32')
        print("from private bytes")
        private = secp256k1.PrivateKey(privkey=private_bytes)
        public = private.pubkey
        public_bytes = public.serialize()
        print("sign_byte: %s" % public.serialize()[:1].hex())
        print("keypair private: %s len: %d" % (private_bytes.hex(),
                                               len(private_bytes)))
        print("keypair derived public_bytes: %s len: %d" % (public_bytes.hex(),
                                                            len(public_bytes)))
        return cls(private=private, public=public, public_bytes=public.serialize())

    @classmethod
    def from_public_bytes(cls, public_bytes):
        print("public bytes: %s len: %d" % (public_bytes.hex(),
                                            len(public_bytes)))
        if len(public_bytes) != 33:
            raise NoiseValueError('Invalid length of public_bytes! '
                                  'Should be 33')
        print("from public bytes")
        signed_bytes = public_bytes
        public = secp256k1.PublicKey(pubkey=signed_bytes, raw=True)
        print("keypair public_bytes: %s" % signed_bytes.hex())
        return cls(public=public, public_bytes=signed_bytes)
