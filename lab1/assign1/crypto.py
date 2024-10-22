#!/usr/bin/env python3 -tt
"""
File: crypto.py
---------------
Assignment 1: Cryptography
Course: CS 41
Name: Turzo Nandor Tibor
ID: tnim2314

Replace this with a description of the program.
"""
import utils

# Caesar Cipher

def encrypt_caesar(plaintext):
    """Encrypt plaintext using a Caesar cipher.

    Add more implementation details here.
    """
    
    if not plaintext:
        raise ValueError("Plaintext must not be empty")
    
    encrypted = ""
    
    for char in plaintext:
        if char.isalpha(): 
            base = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - base + 3) % 26 + base
            encrypted += chr(shifted)
        else:
            encrypted += char
            
    return encrypted


def decrypt_caesar(ciphertext):
    """Decrypt a ciphertext using a Caesar cipher.

    Add more implementation details here.
    """
    
    if not ciphertext:
        raise ValueError("Plaintext must not be empty")
    
    decrypted = ""
    
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - base - 3) % 26 + base
            decrypted += chr(shifted)
        else:
            decrypted += char
            
    return decrypted

# Vigenere Cipher

def encrypt_vigenere(plaintext, keyword):
    """Encrypt plaintext using a Vigenere cipher with a keyword.

    Add more implementation details here.
    """
    
    if not plaintext:
        raise ValueError("Plaintext must not be empty") 
    if not keyword:
        raise ValueError("Keyword must not be empty")
    
    i = 0
    encrypted = ""
    keyword = keyword.upper()
    
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(keyword[i % len(keyword)]) - ord('A')
            encrypted += chr((ord(char) - base + shift) % 26 + base)
            i += 1
        else:
            encrypted += char

    return encrypted


def decrypt_vigenere(ciphertext, keyword):
    """Decrypt ciphertext using a Vigenere cipher with a keyword.

    Add more implementation details here.
    """
    
    if not ciphertext:
        raise ValueError("Plaintext must not be empty")
    if not keyword:
        raise ValueError("Keyword must not be empty")
    
    i = 0
    decrypted = ""
    keyword = keyword.upper()

    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(keyword[i % len(keyword)]) - ord('A')
            decrypted += chr((ord(char) - base - shift) % 26 + base)
            i += 1
        else:
            decrypted += char 

    return decrypted


# Merkle-Hellman Knapsack Cryptosystem

def generate_private_key(n=8):
    """Generate a private key for use in the Merkle-Hellman Knapsack Cryptosystem.

    Following the instructions in the handout, construct the private key components
    of the MH Cryptosystem. This consistutes 3 tasks:

    1. Build a superincreasing sequence `w` of length n
        (Note: you can check if a sequence is superincreasing with `utils.is_superincreasing(seq)`)
    2. Choose some integer `q` greater than the sum of all elements in `w`
    3. Discover an integer `r` between 2 and q that is coprime to `q` (you can use utils.coprime)

    You'll need to use the random module for this function, which has been imported already

    Somehow, you'll have to return all of these values out of this function! Can we do that in Python?!

    @param n bitsize of message to send (default 8)
    @type n int

    @return 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.
    """
    raise NotImplementedError  # Your implementation here

def create_public_key(private_key):
    """Create a public key corresponding to the given private key.

    To accomplish this, you only need to build and return `beta` as described in the handout.

        beta = (b_1, b_2, ..., b_n) where b_i = r × w_i mod q

    Hint: this can be written in one line using a list comprehension

    @param private_key The private key
    @type private_key 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.

    @return n-tuple public key
    """
    raise NotImplementedError  # Your implementation here


def encrypt_mh(message, public_key):
    """Encrypt an outgoing message using a public key.

    1. Separate the message into chunks the size of the public key (in our case, fixed at 8)
    2. For each byte, determine the 8 bits (the `a_i`s) using `utils.byte_to_bits`
    3. Encrypt the 8 message bits by computing
         c = sum of a_i * b_i for i = 1 to n
    4. Return a list of the encrypted ciphertexts for each chunk in the message

    Hint: think about using `zip` at some point

    @param message The message to be encrypted
    @type message bytes
    @param public_key The public key of the desired recipient
    @type public_key n-tuple of ints

    @return list of ints representing encrypted bytes
    """
    raise NotImplementedError  # Your implementation here

def decrypt_mh(message, private_key):
    """Decrypt an incoming message using a private key

    1. Extract w, q, and r from the private key
    2. Compute s, the modular inverse of r mod q, using the
        Extended Euclidean algorithm (implemented at `utils.modinv(r, q)`)
    3. For each byte-sized chunk, compute
         c' = cs (mod q)
    4. Solve the superincreasing subset sum using c' and w to recover the original byte
    5. Reconsitite the encrypted bytes to get the original message back

    @param message Encrypted message chunks
    @type message list of ints
    @param private_key The private key of the recipient
    @type private_key 3-tuple of w, q, and r

    @return bytearray or str of decrypted characters
    """
    raise NotImplementedError  # Your implementation here

def encrypt_scytale(plaintext, circumference):
    """Encrypt the plaintext using the Scytale Cipher with a circumference."""
    
    rows = [''] * circumference     
    for i, char in enumerate(plaintext):
        row = i % circumference
        rows[row] += char

    return ''.join(rows)

def decrypt_scytale(ciphertext, circumference):
    """Decrypt the ciphertext using the Scytale Cipher with a circumference."""
    
    num_rows = (len(ciphertext) + circumference - 1) // circumference

    rows = [''] * circumference
    
    index = 0
    for rail in range(circumference):
        for _ in range(num_rows):
            if index < len(ciphertext):
                rows[rail] += ciphertext[index]
                index += 1

    plaintext = []
    for row in range(num_rows):
        for col in range(circumference):
            if row < len(rows[col]):
                plaintext.append(rows[col][row])

    return ''.join(plaintext)


def encrypt_railfence(plaintext, num_rails):
    """Encrypt the plaintext using the Rail Fence Cipher with a specified number of rails."""
    
    if num_rails == 1:
        return plaintext  
    
    rails = [''] * num_rails
    direction_down = True
    current_rail = 0
    
    for char in plaintext:
        rails[current_rail] += char
        
        if(direction_down):
            current_rail += 1
        else:
            current_rail -= 1
            
        if current_rail == 0 or current_rail == num_rails - 1:
            direction_down = not direction_down
    
    return ''.join(rails)

def decrypt_railfence(ciphertext, num_rails):
    """Decrypt the ciphertext using the Rail Fence Cipher with a specified number of rails."""
    
    if num_rails == 1:
        return ciphertext

    rail_lengths = [0] * num_rails
    direction_down = False
    current_rail = 0

    for _ in range(len(ciphertext)): #kiszamolja mindegyik rail hany karakterbol all
        rail_lengths[current_rail] += 1
        if current_rail == 0 or current_rail == num_rails - 1:
            direction_down = not direction_down
        if direction_down:
            current_rail += 1
        else:
            current_rail -= 1

    rails = [''] * num_rails
    index = 0
 
    for rail in range(num_rails):   #elossza a karaktereket a raileken
        for _ in range(rail_lengths[rail]):
            rails[rail] += ciphertext[index]
            index += 1

    plaintext = []
    current_rail = 0
    direction_down = False

    for _ in range(len(ciphertext)):  #osszeolvassa a szoveget a zigzag modon
        plaintext.append(rails[current_rail][0])
        rails[current_rail] = rails[current_rail][1:]
        if current_rail == 0 or current_rail == num_rails - 1:
            direction_down = not direction_down
        if direction_down:
            current_rail += 1
        else:
            current_rail -= 1

    return ''.join(plaintext)

