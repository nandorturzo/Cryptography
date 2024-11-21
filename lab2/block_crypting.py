import json
from Crypto.Cipher import AES
from custom_modes import CustomModes

class CustomCipher:
    def __init__(self, key: bytes, block_size: int):
        """Initialize the Custom Vigenère Cipher with the key and block size."""
        self.key = key
        self.block_size = block_size

    def _extend_key(self, data):
        key_length = len(self.key)
        data_length = len(data)
        
        repeated_key = self.key * (data_length // key_length)
        remaining_key = self.key[:data_length % key_length]
        extended_key = repeated_key + remaining_key
        
        return extended_key

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt a block using the custom Vigenère cipher logic with extended key."""
        extended_key = self._extend_key(block)
        encrypted_block = [(b + k) % 256 for b, k in zip(block, extended_key)]
        return bytes(encrypted_block)

    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt a block using the custom Vigenère cipher logic with extended key."""
        extended_key = self._extend_key(block)
        decrypted_block = [(b - k) % 256 for b, k in zip(block, extended_key)]
        return bytes(decrypted_block)


class BlockCrypting:
    def __init__(self, config_file):
        """Initialize the BlockCrypting class by loading the config from a JSON file."""
        with open(config_file, 'r') as file:
            config = json.load(file)

        self.block_size = config.get("block_size")
        self.algorithm = config.get("algorithm").upper()
        self.key = config.get("key").encode('utf-8')
        self.mode = config.get("mode")
        self.iv = config.get("iv", None)
        if self.iv:
            self.iv = self.iv.encode()
        self.padding = config.get("padding")
        
        if not self.block_size or not self.algorithm or not self.key or not self.mode or not self.padding:
            raise ValueError("Missing required configuration values.")
        
        if self.mode != "ECB" and not self.iv:
            raise ValueError(f"Mode {self.mode} requires an IV to be provided in the config.")

        if self.algorithm == "AES":
            self.cipher = self._get_aes_cipher()
        elif self.algorithm == "CUSTOM":
            self.cipher = CustomCipher(self.key, self.block_size)
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

        self.modes = CustomModes(self.cipher, self.block_size, self.iv)

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
        padding_len = self.block_size - len(data) % self.block_size
        return data + b'\x80' + b'\x00' * (padding_len - 1)

    def des_padding_remove(self, data):
        if len(data) == 0:
            return data
        return data.rstrip(b'\x00').rstrip(b'\x80')

    def schneier_ferguson_padding(self, data):
        """Schneier-Ferguson padding (n bytes of value n)."""
        pad_length = self.block_size - len(data) % self.block_size
        return data + bytes([pad_length] * pad_length)

    def schneier_ferguson_remove(self, data):
        pad_length = data[-1]
        return data[:-pad_length]

    def encrypt(self, data):
        data = self.apply_padding(data)

        if self.algorithm == "AES":
            cipher = self._get_aes_cipher()
            ciphertext = cipher.encrypt(data)
        elif self.algorithm == "CUSTOM":
            ciphertext = self.custom_encrypt(data)
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

        return ciphertext

    def decrypt(self, data):
        if self.algorithm == "AES":
            cipher = self._get_aes_cipher()
            decrypted_data = cipher.decrypt(data)
        elif self.algorithm == "CUSTOM":
            decrypted_data = self.custom_decrypt(data)
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

        return self.remove_padding(decrypted_data)

    def custom_encrypt(self, data: bytes) -> bytes:
        """Encrypt data using the custom Vigenère cipher, applying block modes."""
        if self.mode == "ECB":
            return self.modes.ecb_encrypt(data)
        elif self.mode == "CBC":
            return self.modes.cbc_encrypt(data)
        elif self.mode == "CFB":
            return self.modes.cfb_encrypt(data)
        elif self.mode == "OFB":
            return self.modes.ofb_encrypt(data)
        elif self.mode == "CTR":
            return self.modes.ctr_encrypt(data)
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")

    def custom_decrypt(self, data: bytes) -> bytes:
        """Decrypt data using the custom Vigenère cipher, applying block modes."""
        if self.mode == "ECB":
            return self.modes.ecb_decrypt(data)
        elif self.mode == "CBC":
            return self.modes.cbc_decrypt(data)
        elif self.mode == "CFB":
            return self.modes.cfb_decrypt(data)
        elif self.mode == "OFB":
            return self.modes.ofb_decrypt(data)
        elif self.mode == "CTR":
            return self.modes.ctr_decrypt(data)
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")


