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
