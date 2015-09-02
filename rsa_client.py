# coding=utf8


import base64
import cStringIO
try:
    from hydra import local_settings as settings
except:
    from hydra import settings

try:
    from M2Crypto import RSA, BIO
except:
    RSA = None
    BIO = None

with open(settings.SZR_PRI_KEY) as pri:
    _pri_data = pri.read()

with open(settings.SZR_PUB_KEY) as pub:
    _pub_data = pub.read()

_pri_bio = BIO.MemoryBuffer(_pri_data)
_pub_bio = BIO.MemoryBuffer(_pub_data)
PRI_KEY = RSA.load_key_bio(_pri_bio)
PUB_KEY = RSA.load_pub_key_bio(_pub_bio)


class RsaClient(object):


    def __init__(self, pub, pri):
        self.pub_key = pub
        self.pri_key = pri


    def private_encrypt(self, message, need_base64=True):
        crypto = self.pri_key.private_encrypt(message, RSA.pkcs1_padding)
        if need_base64:
            crypto = base64.b64encode(crypto)
        return crypto

    def private_chunk_encrypt(self, message, chunk, need_base64=True):
        output = cStringIO.StringIO()
        mb = BIO.MemoryBuffer(message)
        try:
            while mb.readable():
                out = mb.read(chunk)
                output.write(self.pri_key.private_encrypt(out, RSA.pkcs1_padding))
        except:
            mb.close()
            crypto = output.getvalue()

        if need_base64:
            crypto = base64.b64encode(crypto)
        return crypto


    def public_encrypt(self, message, need_base64=True):
        crypto = self.pub_key.public_encrypt(message, RSA.pkcs1_padding)
        if need_base64:
            crypto = base64.b64encode(crypto)
        return crypto

    def private_chunk_decrypt(self, crypto, chunk, need_base64=True):
        if need_base64:
            crypto = base64.b64decode(crypto)

        output = cStringIO.StringIO()
        mb = BIO.MemoryBuffer(crypto)
        try:
            while mb.readable():
                out = mb.read(chunk)
                output.write(self.pri_key.private_decrypt(out, RSA.pkcs1_padding))
        except:
            mb.close()
            return output.getvalue()


    def public_chunk_decrypt(self, crypto, chunk, need_base64=True):
        if need_base64:
            crypto = base64.b64decode(crypto)

        output = cStringIO.StringIO()
        mb = BIO.MemoryBuffer(crypto)
        try:
            while mb.readable():
                out = mb.read(chunk)
                output.write(self.pub_key.public_decrypt(out, RSA.pkcs1_padding))
        except:
            mb.close()
            return output.getvalue()


    def private_decrypt(self, crypto, need_base64=True):
        if need_base64:
            crypto = base64.b64decode(crypto)
        return self.pri_key.private_decrypt(crypto, RSA.pkcs1_padding)


    def public_decrypt(self, crypto, need_base64=True):
        if need_base64:
            crypto = base64.b64decode(crypto)
        return self.pub_key.public_decrypt(crypto, RSA.pkcs1_padding)


rsac = RsaClient(PUB_KEY, PRI_KEY)

if __name__ == "__main__":
    data = rsac.private_encrypt('abc')
    print rsac.public_decrypt(data)
    data = rsac.private_chunk_encrypt('abc', 117)
    print rsac.public_chunk_decrypt(data, 128)
