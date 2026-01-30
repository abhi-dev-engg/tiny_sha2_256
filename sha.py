import hashlib

def sha256_hex_input(hex_string: str) -> str:
    data = bytes.fromhex(hex_string)
    return hashlib.sha256(data).hexdigest()


# Example
hex_msg = "abcd" 
print(sha256_hex_input(hex_msg))
