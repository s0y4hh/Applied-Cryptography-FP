# cryptography_app/utils/crypto_logic.py
import math
import random
import hashlib

# --- XOR Cipher Logic ---
def xor_cipher_process(data_bytes, key_str):
    """
    Encrypts or decrypts data_bytes using XOR cipher.
    Efficient for both small and large files.
    Returns the processed bytes and byte-level details (if data is small text).
    """
    key_bytes = key_str.encode('utf-8', errors='replace')
    if not key_bytes:
        raise ValueError("XOR key cannot be empty.")

    processed_bytes = bytearray()
    byte_details = []
    generate_details = len(data_bytes) < 256

    key_len = len(key_bytes)
    # Use memoryview for efficiency on large files
    mv_data = memoryview(data_bytes)
    for i in range(len(data_bytes)):
        data_byte = mv_data[i]
        key_byte = key_bytes[i % key_len]
        xor_result = data_byte ^ key_byte
        processed_bytes.append(xor_result)

        if generate_details:
            try:
                char_val = chr(data_byte) if 32 <= data_byte <= 126 else f'0x{data_byte:02x}'
                key_char_val = chr(key_byte) if 32 <= key_byte <= 126 else f'0x{key_byte:02x}'
                xor_char_val = chr(xor_result) if 32 <= xor_result <= 126 else f'0x{xor_result:02x}'
            except Exception:
                char_val = f'0x{data_byte:02x}'
                key_char_val = f'0x{key_byte:02x}'
                xor_char_val = f'0x{xor_result:02x}'
            byte_details.append({
                'char': char_val,
                'text_byte_bin': format(data_byte, '08b'),
                'text_byte_val': data_byte,
                'key_char': key_char_val,
                'key_byte_bin': format(key_byte, '08b'),
                'key_byte_val': key_byte,
                'xor_char': xor_char_val,
                'xor_result_bin': format(xor_result, '08b'),
                'xor_result_val': xor_result,
            })

    return bytes(processed_bytes), byte_details

# --- Caesar Cipher Logic ---
def caesar_cipher_process(data_bytes, shifts, operation='encrypt'):
    """
    Encrypts or decrypts data_bytes using a Caesar cipher.
    Efficient for both small and large files.
    """
    output_bytes = bytearray()
    char_details = []
    alphabet_size = 256
    generate_details = len(data_bytes) < 256
    shifts_len = len(shifts)

    for i, byte_val_original in enumerate(data_bytes):
        shift_val = shifts[i % shifts_len]
        if operation == 'encrypt':
            shifted_byte_val = (byte_val_original + shift_val) % alphabet_size
        else:
            shifted_byte_val = (byte_val_original - shift_val + alphabet_size) % alphabet_size
        output_bytes.append(shifted_byte_val)

        if generate_details:
            try:
                original_char_display = chr(byte_val_original) if 32 <= byte_val_original <= 126 else f'0x{byte_val_original:02x}'
                processed_char_display = chr(shifted_byte_val) if 32 <= shifted_byte_val <= 126 else f'0x{shifted_byte_val:02x}'
            except Exception:
                original_char_display = f'0x{byte_val_original:02x}'
                processed_char_display = f'0x{shifted_byte_val:02x}'
            char_details.append({
                'original_char': original_char_display,
                'original_byte': byte_val_original,
                'shift_val': shift_val if operation == 'encrypt' else -shift_val,
                'processed_char': processed_char_display,
                'processed_byte': shifted_byte_val,
                'note': ''
            })

    return bytes(output_bytes), char_details

# --- RSA Cipher Logic ---
def rsa_encrypt_process(message_text, public_key):
    """
    Encrypts a text message using RSA.
    public_key is a tuple (e, n).
    Returns ciphertext as a list of numbers and a string representation.
    """
    e, n = public_key
    message_bytes_ords = [ord(char) for char in message_text]
    if any(m >= n for m in message_bytes_ords):
        raise ValueError(f"Message contains characters (value >= n={n}) that cannot be encrypted directly with this n. Choose larger p,q or ensure message characters have ordinal values less than n.")

    ciphertext_nums = [pow(char_code, e, n) for char_code in message_bytes_ords]
    ciphertext_str_chars = []
    for num in ciphertext_nums:
        if 32 <= num <= 126:
            ciphertext_str_chars.append(chr(num))
        elif 128 <= num <= 255:
            try:
                ciphertext_str_chars.append(bytes([num]).decode('latin-1'))
            except Exception:
                ciphertext_str_chars.append(f"\\x{num:02x}")
        else:
            ciphertext_str_chars.append(f"\\u{num:04x}")
    ciphertext_str = "".join(ciphertext_str_chars)
    return ciphertext_nums, ciphertext_str

def rsa_decrypt_process(ciphertext_nums, private_key):
    """
    Decrypts RSA ciphertext (list of numbers).
    private_key is a tuple (d, n).
    Returns the decrypted message string.
    """
    d, n = private_key
    decrypted_bytes_ords = [pow(num, d, n) for num in ciphertext_nums]
    try:
        decrypted_message = "".join([chr(byte_val) for byte_val in decrypted_bytes_ords])
    except ValueError:
        decrypted_message = "Error: Decrypted data contains non-character values."
    return decrypted_message

# --- Block Cipher (XOR based) Logic ---
def pad_data(data_bytes, block_size_bytes, mode='CMS'):
    """Pads data to be a multiple of block_size_bytes."""
    padding_len = block_size_bytes - (len(data_bytes) % block_size_bytes)
    if mode == 'CMS' and len(data_bytes) % block_size_bytes == 0:
        padding_len = block_size_bytes
    elif len(data_bytes) % block_size_bytes == 0 and padding_len == block_size_bytes:
        return data_bytes, b''
    if mode == 'CMS':
        padding = bytes([padding_len] * padding_len)
    elif mode == 'Null':
        padding = b'\x00' * padding_len
    elif mode == 'Space':
        padding = b' ' * padding_len
    elif mode == 'RandomBits':
        padding = bytes(random.getrandbits(8) for _ in range(padding_len))
    else:
        padding = bytes([padding_len] * padding_len)
    return data_bytes + padding, padding

def unpad_data(padded_data_bytes, block_size_bytes, mode='CMS'):
    """Removes padding from data."""
    if not padded_data_bytes:
        return b""
    if mode == 'CMS':
        padding_len = padded_data_bytes[-1]
        if padding_len == 0 or padding_len > block_size_bytes:
            raise ValueError(f"Invalid CMS padding: padding_len ({padding_len}) is zero or too large for block size ({block_size_bytes}).")
        if len(padded_data_bytes) < padding_len:
            raise ValueError(f"Invalid CMS padding: data length ({len(padded_data_bytes)}) is less than padding_len ({padding_len}).")
        if not all(p == padding_len for p in padded_data_bytes[-padding_len:]):
            raise ValueError("Invalid CMS padding: padding bytes do not match padding_len.")
        return padded_data_bytes[:-padding_len]
    elif mode == 'Null':
        i = len(padded_data_bytes) - 1
        while i >= 0 and padded_data_bytes[i] == 0:
            i -= 1
        return padded_data_bytes[:i+1]
    elif mode == 'Space':
        i = len(padded_data_bytes) - 1
        while i >= 0 and padded_data_bytes[i] == ord(' '):
            i -= 1
        return padded_data_bytes[:i+1]
    elif mode == 'RandomBits':
        raise ValueError("Unpadding 'RandomBits' is not supported without original length information.")
    else:
        return padded_data_bytes

def block_cipher_process(data, key_str, block_size_bits, padding_mode, operation, show_details=False):
    """
    Processes data using a simple XOR-based block cipher.
    Optimized for large files and memory efficiency.
    """
    if block_size_bits % 8 != 0:
        raise ValueError("Block size must be a multiple of 8 bits.")
    block_size_bytes = block_size_bits // 8
    key_bytes = key_str.encode('utf-8', errors='replace')
    if not key_bytes:
        raise ValueError("Block cipher key cannot be empty.")
    block_key = (key_bytes * (block_size_bytes // len(key_bytes) + 1))[:block_size_bytes]
    details = []
    processed_data = bytearray()

    if operation == 'encrypt':
        padded_data, padding_bytes = pad_data(data, block_size_bytes, padding_mode)
        if show_details:
            details.append(f"Original data ({len(data)} bytes): {data[:64].hex()}{'...' if len(data) > 64 else ''}")
            details.append(f"Padding mode: {padding_mode}, Block size: {block_size_bytes} bytes")
            details.append(f"Padding added ({len(padding_bytes)} bytes): {padding_bytes.hex()}")
            details.append(f"Padded data ({len(padded_data)} bytes): {padded_data[:64].hex()}{'...' if len(padded_data) > 64 else ''}")
        data_to_process = padded_data
    else:
        data_to_process = data

    if show_details:
        details.append(f"Key used for blocks ({len(block_key)} bytes): {block_key.hex()}")

    if len(data_to_process) % block_size_bytes != 0 and operation == 'decrypt':
        details.append(f"Warning: Decryption input data length ({len(data_to_process)}) is not a multiple of block size ({block_size_bytes}). Results may be incorrect.")

    mv_data = memoryview(data_to_process)
    for i in range(0, len(data_to_process), block_size_bytes):
        block = mv_data[i:i+block_size_bytes]
        current_block_key = block_key if len(block) == block_size_bytes else block_key[:len(block)]
        processed_block = bytes(b ^ k for b, k in zip(block, current_block_key))
        processed_data.extend(processed_block)
        if show_details:
            details.append(f"Block {i//block_size_bytes + 1}:")
            details.append(f"  Input Block  ({len(block)} bytes): {block.tobytes().hex()}")
            details.append(f"  XORed Block ({len(processed_block)} bytes): {processed_block.hex()}")

    if operation == 'decrypt':
        try:
            final_data = unpad_data(bytes(processed_data), block_size_bytes, padding_mode)
            if show_details:
                details.append(f"Decrypted data before unpadding ({len(processed_data)} bytes): {processed_data[:64].hex()}{'...' if len(processed_data) > 64 else ''}")
                details.append(f"Unpadding mode: {padding_mode}")
                details.append(f"Unpadded data ({len(final_data)} bytes): {final_data[:64].hex()}{'...' if len(final_data) > 64 else ''}")
        except ValueError as e:
            if show_details:
                details.append(f"Unpadding Error: {str(e)}. Returning raw decrypted data.")
            final_data = bytes(processed_data)
    else:
        final_data = bytes(processed_data)

    return final_data, details

# --- Hashing Functions ---
def hash_data(data_bytes, algorithm):
    """
    Hashes data_bytes using the specified algorithm.
    Supported algorithms: 'md5', 'sha1', 'sha256', 'sha512'.
    Returns the hex digest of the hash.
    """
    if algorithm == 'md5':
        hasher = hashlib.md5()
    elif algorithm == 'sha1':
        hasher = hashlib.sha1()
    elif algorithm == 'sha256':
        hasher = hashlib.sha256()
    elif algorithm == 'sha512':
        hasher = hashlib.sha512()
    else:
        raise ValueError(f"Unsupported hashing algorithm: {algorithm}. Supported: md5, sha1, sha256, sha512.")
    hasher.update(data_bytes)
    return hasher.hexdigest()
