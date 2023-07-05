#!/usr/bin/env python3
#
# FortiCrack by Bishop Fox Team X
#
# Derive encryption keys from Fortinet firmware images
# using a known plaintext attack, then decrypt them

import sys
import os
import re
import subprocess
import multiprocessing
import functools

# Standard block size for Fortinet firmware images
BLOCK_SIZE = 512


# Load a firmware image into memory (decompressing if necessary)
def load_image_data(image_file):
    try:
        if not os.path.isfile(image_file):
            raise ValueError("file not found")

        # Use gunzip because the Python gzip library won't ignore file signature data
        result = subprocess.run(
            [
                f"gunzip",
                "--to-stdout",  # decompress to stdout and leave the file intact
                "--force",  # allow uncompressed data to pass through
                image_file,
            ],
            check=False,  # ignore trailing garbage warning
            capture_output=True,
        )
        if result.stdout:
            print("[+] Loaded image data")
            return result.stdout
        else:
            raise ValueError("empty file")

    except Exception as err:
        print(f"[-] Failed to load image data: {err}")
        return None


# Validate a derived key by checking against known key values
def validate_key(key):
    # Length must be 32 bytes
    if len(key) != 32:
        return False

    # Key must be an ASCII string
    try:
        string = key.decode("ascii")
    except:
        return False

    # Key bytes only include characters 0-9, A-Z, and a-z
    for char in string:
        valid = re.match(r"[0-9A-Za-z]", char)
        if not valid:
            return False

    # Valid key
    return True


# Derive one byte of the key from two consecutive bytes of ciphertext,
#   one byte of known plaintext, and the key offset
# This is the same XOR operation used in Fortinet's encryption function,
#   but the plaintext and key are swapped
def derive_key_byte(
    key_offset, ciphertext_byte, previous_ciphertext_byte, known_plaintext
):
    key_byte = (
        previous_ciphertext_byte ^ (known_plaintext + key_offset) ^ ciphertext_byte
    )
    key_byte = (key_byte + 256) & 0xFF  # mod 256 to loop negatives
    return key_byte


# Use a known plaintext attack to derive a key from the first 80 bytes of a 512-byte
#   ciphertext block, then decrypt the block header and validate the content
# Known plaintext is 32 null bytes starting from block offset 48
# Only return a key if the decrypted content is valid
def derive_block_key(ciphertext):
    key = bytearray()
    known_plaintext = 0x00

    # Derive the key for this block
    for i in range(32):
        key_offset = (i + 16) % 32  # mod 32 to wrap around key
        plaintext_offset = i + 48
        ciphertext_byte = ciphertext[plaintext_offset]
        previous_ciphertext_byte = ciphertext[plaintext_offset - 1]
        key.append(
            derive_key_byte(
                key_offset, ciphertext_byte, previous_ciphertext_byte, known_plaintext
            )
        )
    key = key[16:] + key[:16]  # swap the first/second halves of the key

    # Validate the key
    if validate_key(key):
        # Decrypt the header and validate contents
        cleartext = decrypt(ciphertext, key)
        if validate_decryption(cleartext):
            print(f"[+] Found key: {key.decode('utf-8')}")
            print(f"[+] Validated: {cleartext[16:46].decode('utf-8')}")
            return bytes(key)

    # Key was invalid
    return None


# Use multiprocessing to attempt key derivation on all 512-byte blocks in parallel
def derive_key(ciphertext):
    # Determine the number of blocks to read
    num_blocks = (len(ciphertext) + BLOCK_SIZE - 1) // BLOCK_SIZE
    block_header_size = 80

    # Create a pool of worker processes
    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        # Start the workers
        results = [
            pool.apply_async(
                derive_block_key,
                (  # Each worker attacks the 80-byte header of a 512-byte block
                    ciphertext[
                        block_num * BLOCK_SIZE : block_num * BLOCK_SIZE
                        + block_header_size
                    ],
                ),
            )
            for block_num in range(num_blocks)
        ]
        # Look for a successful result
        for result in results:
            key = result.get()
            if key:
                # Kill the workers as soon as we find a valid key
                pool.terminate()
                pool.join()
                return key
    return None


# Validate decryption by checking for known header data
# NOTE: this header isn't always in the first 512-byte block
def validate_decryption(cleartext):
    if (
        # Length must be at least 80 chars
        len(cleartext) >= 80
        # Validate the file signature "magic bytes"
        and cleartext[12:16] == b"\xff\x00\xaa\x55"
    ):
        # Make sure the image name is readable
        try:
            image_name = cleartext[16:46].decode("utf-8", errors="strict")
        except:
            return False
        # Make sure the word "build" is in the image name
        if "build" in image_name.lower():
            # Valid Fortinet image
            return True
    # Unknown format
    return False


# Decrypt data
def decrypt(ciphertext, key, num_bytes=None):
    if num_bytes is None or num_bytes > len(ciphertext):
        num_bytes = len(ciphertext)
    if num_bytes > BLOCK_SIZE:
        num_bytes = BLOCK_SIZE

    key_offset = 0
    block_offset = 0
    cleartext = bytearray()
    previous_ciphertext_byte = 0xFF  # IV is always FF

    while block_offset < num_bytes:
        # If we're testing a partial key, return partial cleartext
        if key_offset >= len(key):
            return bytes(cleartext)

        # For each byte in the block, bitwise XOR the current byte with the
        # previous byte (both ciphertext) and the corresponding key byte
        ciphertext_byte = ciphertext[block_offset]
        xor = (
            previous_ciphertext_byte ^ ciphertext_byte ^ key[key_offset]
        ) - key_offset  # subtract the key offset to undo obfuscation
        xor = (xor + 256) & 0xFF  # mod 256 to loop negatives
        cleartext.append(xor)

        # Proceed to next byte
        block_offset += 1
        key_offset = (
            key_offset + 1  # increment key offset
        ) & 0x1F  # mod 32 to loop around the key
        previous_ciphertext_byte = ciphertext_byte

    # Reached end of block
    return bytes(cleartext)


# Use multiprocessing to decrypt all 512-byte blocks in parallel
def decrypt_file(ciphertext, key, output_file):
    # Determine the number of blocks to read
    num_blocks = (len(ciphertext) + BLOCK_SIZE - 1) // BLOCK_SIZE

    # Create a pool of worker processes
    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        worker = functools.partial(decrypt, key=key)
        worker_map = pool.map_async(
            worker,
            [  # Each worker gets a 512-byte block of ciphertext to decrypt
                ciphertext[block_num * BLOCK_SIZE : block_num * BLOCK_SIZE + BLOCK_SIZE]
                for block_num in range(num_blocks)
            ],
        )
        worker_map.wait()
        results = worker_map.get()
    if not results:
        return False

    # Write the ordered results to the output file
    cleartext = b"".join(results)
    with open(output_file, "wb") as outfile:
        outfile.write(cleartext)
    return True


def main():
    # Parse input
    if len(sys.argv) < 2 or sys.argv[1] in ["-h", "--help"]:
        print("Usage: python3 forticrack.py <FILENAME>")
        sys.exit(0)
    encrypted_file = sys.argv[1]
    decrypted_file = f"{os.path.splitext(encrypted_file)[0]}.decrypted"

    # Print banner
    print(
        " ___  __   __  ___    __   __        __       \n|__  /  \ |__)  |  | /  ` |__)  /\  /  ` |__/ \n|    \__/ |  \  |  | \__, |  \ /~~\ \__, |  \ \n"
    )
    print(f"[+] Decrypting {encrypted_file}")

    # Decompress the input file
    ciphertext = load_image_data(encrypted_file)
    if not ciphertext:
        sys.exit(1)

    # Make sure it's encrypted
    for block_offset in range(0, len(ciphertext), BLOCK_SIZE):
        if validate_decryption(ciphertext[block_offset : block_offset + 80]):
            print("[!] Image is already cleartext")
            sys.exit(0)

    # Identify the key using a known plaintext attack
    key = derive_key(ciphertext)
    if key:
        # Decrypt the file
        if decrypt_file(ciphertext, key, decrypted_file):
            print(f"[+] Decrypted: {decrypted_file}")
        else:
            print("[-] Decryption failed")
            sys.exit(1)
    else:
        print("[-] No valid key found")
        sys.exit(1)


if __name__ == "__main__":
    main()
