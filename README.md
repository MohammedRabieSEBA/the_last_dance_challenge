# Cryptography Challenge - Decrypting XOR Encrypted Messages

This project solves a cryptography challenge where we need to decrypt a hidden flag using XOR encryption. The goal of this challenge is to recover the flag by XORing multiple ciphertexts with a known message.

## Challenge Overview

The challenge provides us with two ciphertexts that were encrypted using the same key and a known plaintext message. We are tasked with using the XOR operation to reveal the hidden flag. XOR encryption is commonly used in cryptography, especially in Capture the Flag (CTF) competitions, because of its reversible nature.

The provided ciphertexts were encrypted using the **ChaCha20 cipher** and the same nonce and key. Our goal is to decrypt these ciphertexts and extract the flag.

## Solution

### Steps

1. **Understanding the Encryption**:
   - The ciphertexts were generated using the **ChaCha20** stream cipher. However, instead of decrypting the ciphertexts directly with ChaCha20, we use XOR between two ciphertexts and a known plaintext message.
   
2. **Using XOR Decryption**:
   - XOR is a simple reversible encryption technique. If we XOR the ciphertext with the key or the plaintext message, we can retrieve the original message.
   - In this case, by XORing the two given ciphertexts with the known message, we can reveal the hidden flag.

3. **Code Walkthrough**:
   - The solution leverages the `pwn` Python module, which simplifies the XOR operation.
   - The ciphertexts and the known message are first converted from hexadecimal format to bytes.
   - We then apply XOR between the ciphertexts and the known message to reveal the flag.

### Code Implementation

Here is the Python code used to solve the challenge:

```python
import pwn

# Encrypted hex strings provided in the challenge
hex_ciphertext_1 = "7aa34395a258f5893e3db1822139b8c1f04cfab9d757b9b9cca57e1df33d093f07c7f06e06bb6293676f9060a838ea138b6bc9f20b08afeb73120506e2ce7b9b9dcd9e4a421584cfaba2481132dfbdf4216e98e3facec9ba199ca3a97641e9ca9782868d0222a1d7c0d3119b867edaf2e72e2a6f7d344df39a14edc39cb6f960944ddac2aaef324827c36cba67dcb76b22119b43881a3f1262752990"
hex_ciphertext_2 = "7d8273ceb459e4d4386df4e32e1aecc1aa7aaafda50cb982f6c62623cf6b29693d86b15457aa76ac7e2eef6cf814ae3a8d39c7"

# The known message (plaintext) that was encrypted to form ciphertext_1
known_message = b"Our counter agencies have intercepted your messages and a lot "
known_message += b"of your agent's identities have been exposed. In a matter of "
known_message += b"days all of them will be captured"

# Convert the hex-encoded ciphertexts to byte format
ciphertext_1 = bytes.fromhex(hex_ciphertext_1)
ciphertext_2 = bytes.fromhex(hex_ciphertext_2)

# Perform XOR between ciphertext_1, ciphertext_2, and the known message
decrypted_message = pwn.xor(ciphertext_1, ciphertext_2, known_message)

# Print the resulting flag (decrypted message)
print("FLAG: ", decrypted_message)
# Cryptography Challenge - Decrypting XOR Encrypted Messages

This project solves a cryptography challenge where we need to decrypt a hidden flag using XOR encryption. The goal of this challenge is to recover the flag by XORing multiple ciphertexts with a known message.

## Challenge Overview

The challenge provides us with two ciphertexts that were encrypted using the same key and a known plaintext message. We are tasked with using the XOR operation to reveal the hidden flag. XOR encryption is commonly used in cryptography, especially in Capture the Flag (CTF) competitions, because of its reversible nature.

The provided ciphertexts were encrypted using the **ChaCha20 cipher** and the same nonce and key. Our goal is to decrypt these ciphertexts and extract the flag.

## Solution

### Steps

1. **Understanding the Encryption**:
   - The ciphertexts were generated using the **ChaCha20** stream cipher. However, instead of decrypting the ciphertexts directly with ChaCha20, we use XOR between two ciphertexts and a known plaintext message.
   
2. **Using XOR Decryption**:
   - XOR is a simple reversible encryption technique. If we XOR the ciphertext with the key or the plaintext message, we can retrieve the original message.
   - In this case, by XORing the two given ciphertexts with the known message, we can reveal the hidden flag.

### How the Code Works:

#### Hexadecimal Conversion:

The ciphertexts (`hex_ciphertext_1` and `hex_ciphertext_2`) are provided as hexadecimal strings. We convert them to bytes using `bytes.fromhex()` so that we can process them.

#### XOR Operation:

We use the `pwn.xor()` function to XOR the two ciphertexts along with the known plaintext (`known_message`). This operation reveals the hidden message (the flag) after performing the XOR on the provided data.

#### Output:

The output is printed using `print()`, and it will display the flag in the form of a decrypted message.

### Expected Output:

When you run the code, you should see the following output (depending on the challenge's flag):

