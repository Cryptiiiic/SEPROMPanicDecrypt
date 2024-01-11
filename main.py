#!/usr/bin/env python3

from Crypto.Cipher import AES
from binascii import hexlify, unhexlify
import sys


class SEPROMPanicDecrypt:
    _soc = ""
    _panic = b""
    _keys = []
    _is_32bit = False
    _is_old_style_panic = False

    def __init__(self, soc, panic):

        self._soc = soc.lower()
        soc_int = int(self._soc[1:], 16)
        if soc_int < 0x8015:
            self._is_32bit = True
        if soc_int < 0x8000:
            self._is_old_style_panic = True
        self._panic = bytes.fromhex(panic)
        self._keys = {
            "t7000": bytes.fromhex("1a3f5e7c676ae321cc3d501212c36a21b453f6788dfe32f154a210fa92b36e21"),     # a8
            "t7001": bytes.fromhex("1a3f5e7c676ae321cc3d501212c36a21b453f6788dfe32f154a210fa92b36e21"),     # a8x
            "s8000": bytes.fromhex("ac884aef3f99476caf8f1254158bbf3dd3e48446c8e906e1c224a8c6318e4589"),     # a9(Samsung)
            "s8001": bytes.fromhex("ac884aef3f99476caf8f1254158bbf3dd3e48446c8e906e1c224a8c6318e4589"),     # a9x
            "s8003": bytes.fromhex("ac884aef3f99476caf8f1254158bbf3dd3e48446c8e906e1c224a8c6318e4589"),     # a9(TSMC)
            "t8006": bytes.fromhex("99f095abe48158ee3a0c72035f06ac3fdd1a5ff66365795ecbbe2e24d35c5315"),     # S4/S5
            "t8010": bytes.fromhex("ca80933cb9368b168f5a0699f9eea44079fe9e89f0df5db12dc2fe67cfd8350c"),     # a10
            "t8011": bytes.fromhex("6f94ca7e9e97e9cdb68099ccd8943937758011a853d2f9be5bedb317357be675"),     # a10x
            # "t8012": bytes.fromhex("?"),                                                                  # T2 Chip
            # "t8015": bytes.fromhex("?"),                                                                  # a11
            "t8020": bytes.fromhex("2e2e535499d89b8f997ebc8dc1e1122b0aa97f9401be4275c10934002d6a779f"),     # a12
            "t8027": bytes.fromhex("f0ee42ef0504e17258c2379113effe6a8ef3e11a8bec2156c2e88203b6665023"),     # a12z/x
            "t8030": bytes.fromhex("8d12eb734a8550ad37b68b260ef74211217bddc0a5b09fae09bd26b7b1cfcf68"),     # a13
            "t8101": bytes.fromhex("79d0ae2369a6dc8866deb5aa19fc696e62eb0d6940677bec25f144dcada93be1"),     # a14
            "t8103": bytes.fromhex("d3a3e9b2920d8da5767a5a31ebaa1022b2ba25d8dd7df1afea4735b84f46e7fc"),     # M1
            "t8110": bytes.fromhex("ab7be133e8a3a2f7d16bf9a8e6d23c66b86271e0572d47f623e2de4485c674c3"),     # a15
            "t8112": bytes.fromhex("500e80afe77ededb439cc278dfb018b9a7b14606743baa69d0af9e72b6ac802a"),     # M2
            # "t8120": bytes.fromhex("?"),                                                                  # a16
            # "t8122": bytes.fromhex("?"),                                                                  # M3
            # "t8130": bytes.fromhex("?"),                                                                  # a17
        }
        if self._soc not in self._keys:
            print(f"\nUnsupported SoC: ({self._soc})!")
            exit(-4)
        self._key = self._keys[self._soc]
        self._iv = bytes.fromhex("".zfill(32))
        self._trng_key = self.trng_key()

    def trng_key(self):
        trng_key = self._panic[:8]
        self._panic = self._panic[8:] if not self._is_old_style_panic else self._panic
        return trng_key

    def create_encrypt_data(self, index):
        return index.to_bytes(8, 'little') + self._trng_key

    def decrypt_old(self):
        aes = AES.new(self._key, AES.MODE_CBC, self._iv)
        decrypted_data = aes.decrypt(self._panic)
        for i in range(0, len(self._panic), 4):
            result = int.from_bytes(decrypted_data[i:(i + 4)], byteorder="little")
            print(f"0x{result:08X}")


    def decrypt(self):

        if self._is_old_style_panic:
            self.decrypt_old()
            return

        loop_len = (int((len(self._panic) / 8) / 2))
        for i in range(0, loop_len, 1):
            data = self.create_encrypt_data(i)
            aes = AES.new(self._key, AES.MODE_CBC, self._iv)
            encrypted_data = aes.encrypt(data)

            xor = self._panic[(i * 16):((i * 16) + 16)]

            xor_key1 = int.from_bytes(encrypted_data[:8], byteorder="big")
            xor_key2 = int.from_bytes(encrypted_data[8:], byteorder="big")

            xor_int1 = int.from_bytes(xor[:8], byteorder="big")
            xor_int2 = int.from_bytes(xor[8:16], byteorder="big")

            result1 = xor_key1 ^ xor_int1
            result2 = xor_key2 ^ xor_int2

            result1 = result1.to_bytes(8, "big")
            result2 = result2.to_bytes(8, "big")

            if self._is_32bit:
                tmp1 = result1
                tmp2 = result2
                result1 = tmp1[:4]
                result2 = tmp1[4:]
                result3 = tmp2[:4]
                result4 = tmp2[4:]

                result1 = int.from_bytes(result1, "little")
                result2 = int.from_bytes(result2, "little")
                result3 = int.from_bytes(result3, "little")
                result4 = int.from_bytes(result4, "little")

                print(f"0x{result1:08X}")
                print(f"0x{result2:08X}")
                print(f"0x{result3:08X}")
                print(f"0x{result4:08X}")
            else:
                result1 = int.from_bytes(result1, "little")
                result2 = int.from_bytes(result2, "little")

                print(f"0x{result1:016X}")
                print(f"0x{result2:016X}")
            del aes


def main():
    if len(sys.argv) < 3:
        argv0 = sys.argv[0]
        print(f"Usage: {argv0} <SoC> <SEPROM Panic Bytes>")
        exit(-1)
    if len(sys.argv[1]) < 5 or len(sys.argv[1]) >= 7:
        argv1 = sys.argv[1]
        print(f"\nInvalid SoC: ({argv1})!")
        exit(-2)
    if len(sys.argv[2]) > 2 and sys.argv[2][:2] == "0x":
        sys.argv[2] = sys.argv[2][2:]
    if len(sys.argv[2]) < 64 or len(sys.argv[2]) % 4 != 0:
        argv2 = sys.argv[2]
        print(f"\nInvalid SEPROM Panic Bytes: ({argv2})!")
        exit(-3)
    s = SEPROMPanicDecrypt(str(sys.argv[1]), str(sys.argv[2]))
    s.decrypt()
    return


if __name__ == '__main__':
    main()
