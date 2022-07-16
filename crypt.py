# crypto
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet
import cryptography.exceptions
from base64 import a85decode, a85encode, urlsafe_b64encode
from main import Asm
from common import msgpack

# create or read an ec key from the database
class CryptoInit:
    def __init__(self, password, pem=False):
        self.__password = password.encode()
        self.pem = pem

        if self.pem:
            self.__load_ec_key()
        else:
            self.__create_ec_key()
        self.public_key = self.private_key.public_key()

    def __load_ec_key(self):
        self.private_key = serialization.load_pem_private_key(
            self.pem.encode(),
            password=self.__password,
        )

    def __create_ec_key(self):
        self.private_key = ec.generate_private_key(
            # use a 256 bit ec key for now (should provide enough security)
            ec.SECP256R1()
        )

        self.pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(self.__password)
        ).decode()

# encoding/decoding of the NscID (USR packets)
class UserPacket:
    def __init__(self, packet):
        self.packet = packet
    
    def decode(self):
        raw = msgpack.loads(
            a85decode(self.packet.encode())
        )
        pub_pem = PubSwap.obj_to_pem(
            PubSwap.der_to_obj(raw[1])
        )
        encoded_sig = a85encode(raw[2]).decode()
        
        new = Asm.user_packet(raw[0], pub_pem, encoded_sig)
        return new
    
    def encode(self):
        pub_bytes = PubSwap.obj_to_der(
            PubSwap.pem_to_obj(self.packet['PubKey'])
        )
        sig_bytes = a85decode(self.packet['Signature'].encode())
        
        new = [self.packet['Username'], pub_bytes, sig_bytes]

        return a85encode(
            msgpack.dumps(new)
        ).decode()

# Swap around public keys (EC) into various formats 
class PubSwap:
    def obj_to_der(obj):
        return obj.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def obj_to_pem(obj):
        return obj.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def der_to_obj(der):
        return serialization.load_der_public_key(
            der
        )

    def pem_to_obj(pem):
        return serialization.load_pem_public_key(
            pem.encode()
        )

# create and verify signatures
class Crypto:
    def sign(pr_key, message):
        signature = pr_key.sign(
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return a85encode(signature).decode()
    
    def verify(public_key, signature, message):
        try:
            public_key.verify(
                a85decode(signature.encode()),
                message.encode(),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except cryptography.exceptions.InvalidSignature:
            return False

def checkUsername(name):
    if type(name) == str:
        if all(ord(c) < 128 for c in name) and len(name) <= 16:
            return True
