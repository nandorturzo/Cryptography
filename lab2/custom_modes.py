class CustomModes:
    def __init__(self, cipher, block_size, iv):
        self.cipher = cipher
        self.block_size = block_size
        self.iv = iv
        
    def _xor_bytes(self, block, iv_block):
        """Helper function to XOR two byte blocks."""
        return bytes(x ^ y for x, y in zip(block, iv_block))


    def ecb_encrypt(self, data):
        """ECB mode encryption."""
        encrypted = b""
        block_size = self.block_size//8
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            encrypted_block = self.cipher.encrypt_block(block)
            encrypted += encrypted_block
        return encrypted

    def ecb_decrypt(self, data):
        """ECB mode decryption."""
        decrypted = b""
        block_size = self.block_size//8
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            decrypted_block = self.cipher.decrypt_block(block)
            decrypted += decrypted_block
        return decrypted

    def cbc_encrypt(self, data):
        """CBC mode encryption."""
        previous_block = self.iv
        encrypted = b""
        block_size = self.block_size//8
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            block = self._xor_bytes(block, previous_block)
            encrypted_block = self.cipher.encrypt_block(block)
            encrypted += encrypted_block
            previous_block = encrypted_block
        return encrypted

    def cbc_decrypt(self, data):
        """CBC mode decryption."""
        previous_block = self.iv
        decrypted = b""
        block_size = self.block_size//8
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            decrypted_block = self.cipher.decrypt_block(block)
            decrypted_block = self._xor_bytes(decrypted_block, previous_block)
            decrypted += decrypted_block
            previous_block = block
        return decrypted

    def cfb_encrypt(self, data):
        """CFB mode encryption."""
        previous_block = self.iv
        encrypted = b""
        block_size = self.block_size//8
        for i in range(0, len(data), block_size):
            encrypted_block = self.cipher.encrypt_block(previous_block)
            block = data[i:i + block_size]
            encrypted_block_xor = self._xor_bytes(block, encrypted_block)
            encrypted += encrypted_block_xor
            previous_block = encrypted_block
        return encrypted

    def cfb_decrypt(self, data):
        """CFB mode decryption."""
        previous_block = self.iv
        decrypted = b""
        block_size = self.block_size//8
        for i in range(0, len(data), block_size):
            decrypted_block = self.cipher.decrypt_block(previous_block)
            block = data[i:i + block_size]
            decrypted_block_xor = self._xor_bytes(block, decrypted_block)
            decrypted += decrypted_block_xor
            previous_block = block
        return decrypted

    def ofb_encrypt(self, data):
        """OFB mode encryption."""
        previous_block = self.iv
        encrypted = b""
        block_size = self.block_size//8
        for i in range(0, len(data), block_size):
            previous_block = self.cipher.encrypt_block(previous_block)
            block = data[i:i + block_size]
            encrypted_block = self._xor_bytes(block, previous_block)
            encrypted += encrypted_block
        return encrypted

    def ofb_decrypt(self, data):
        """OFB mode decryption (same as encryption)."""
        return self.ofb_encrypt(data)

    def ctr_encrypt(self, data):
        """CTR mode encryption."""
        counter = int.from_bytes(self.iv, 'big')
        encrypted = b""
        block_size = self.block_size//8
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            counter_block = counter.to_bytes(block_size, 'big')
            encrypted_counter = self.cipher.encrypt_block(counter_block)
            xor_block = self._xor_bytes(block, encrypted_counter)
            encrypted += xor_block
            counter += 1
        return encrypted

    def ctr_decrypt(self, data):
        """CTR mode decryption (same as encryption)."""
        return self.ctr_encrypt(data)
