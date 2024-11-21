import json
from Crypto.Cipher import AES 


class BlockCrypting:
    def __init__(self, config_file):
        """Initialize the BlockCrypting class by loading the config from a JSON file."""
        with open(config_file, 'r') as file:
            config = json.load(file)

        self.block_size = config.get("block_size")
        self.algorithm = config.get("algorithm")
        self.key = config.get("key").encode('utf-8')
        self.mode = config.get("mode")
        self.iv = config.get("iv",None)
        if self.iv:
            self.iv = self.iv.encode()
        self.padding = config.get("padding")
        
        if not self.block_size or not self.algorithm or not self.key or not self.mode or not self.padding:
            raise ValueError("Missing required configuration values.")

        if self.mode != "ECB" and not self.iv:
            raise ValueError(f"Mode {self.mode} requires an IV to be provided in the config.")

    def apply_padding(self, data):
        if self.padding == "Zero-padding":
            return self.zero_padding(data)
        elif self.padding == "DES padding":
            return self.des_padding(data)
        elif self.padding == "Schneier-Ferguson padding":
            return self.schneier_ferguson_padding(data)
        else:
            raise ValueError(f"Unsupported padding scheme: {self.padding}")

    def remove_padding(self, data):
        if self.padding == "Zero-padding":
            return self.zero_padding_remove(data)
        elif self.padding == "DES padding":
            return self.des_padding_remove(data)
        elif self.padding == "Schneier-Ferguson padding":
            return self.schneier_ferguson_remove(data)
        else:
            raise ValueError(f"Unsupported padding scheme: {self.padding}")

    def zero_padding(self, data):
        """Zero-padding."""
        return data + b'\x00' * (self.block_size - len(data) % self.block_size)

    def zero_padding_remove(self, data):
        return data.rstrip(b'\x00')

    def des_padding(self, data):
        """DES padding (1 byte with value 0x01, followed by 0x00 bytes)."""
        pad_length = 8 - len(data) % 8
        return data + bytes([0x01]) + b'\x00' * (pad_length - 1)

    def des_padding_remove(self, data):
        if len(data) == 0:
            return data
        return data.rstrip(b'\x00').rstrip(b'\x01')

    def schneier_ferguson_padding(self, data):
        """Schneier-Ferguson padding (n bytes of value n)."""
        pad_length = self.block_size - len(data) % self.block_size
        return data + bytes([pad_length] * pad_length)

    def schneier_ferguson_remove(self, data):
        pad_length = data[-1]
        return data[:-pad_length]


    def _get_aes_cipher(self):
        """Return an AES cipher object based on the selected mode."""
        if self.mode == "ECB":
            return AES.new(self.key, AES.MODE_ECB)
        elif self.mode == "CBC":
            return AES.new(self.key, AES.MODE_CBC, self.iv)
        elif self.mode == "CFB":
            return AES.new(self.key, AES.MODE_CFB, self.iv)
        elif self.mode == "OFB":
            return AES.new(self.key, AES.MODE_OFB, self.iv)
        elif self.mode == "CTR":
            return AES.new(self.key, AES.MODE_CTR, nonce=self.iv[:8])
        else:
            raise ValueError(f"Unsupported AES mode: {self.mode}")

    def encrypt(self, data):
        data = self.apply_padding(data)

        if self.algorithm == "AES":
            cipher = self._get_aes_cipher()
            ciphertext = cipher.encrypt(data)
        elif self.algorithm == "Custom":
            ciphertext = self.custom_encrypt(data)
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

        return ciphertext

    def decrypt(self, data):
        if self.algorithm == "AES":
            cipher = self._get_aes_cipher()
            decrypted_data = cipher.decrypt(data)
        elif self.algorithm == "Custom":
            decrypted_data = self.custom_decrypt(data)
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

        return self.remove_padding(decrypted_data)

def read_gif(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

def write_gif(file_path, data):
    with open(file_path, 'wb') as file:
        file.write(data)

if __name__ == "__main__":
    crypt = BlockCrypting("./config/config5.json")

    input = read_gif("./input/mikulas.gif")
    encrypted = crypt.encrypt(input)

    decrypted = crypt.decrypt(encrypted)
    write_gif("./output/mikulasEncrypted.gif",decrypted)
