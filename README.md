# Kryptos: Applied Cryptography Interactive Learning Platform

![Kryptos Banner](https://github.com/s0y4hh/Applied-Cryptography-FP/blob/main/static/images/banner.png?raw=true)

## 🌟 Online Access

**Try it now:** [https://kryptos-036bc940920f.herokuapp.com](https://kryptos-036bc940920f.herokuapp.com)

## Applied Cryptography Final Project

_May 2025_

### Group Members

1
2
3
4

## Introduction

Kryptos is an interactive web application designed to demonstrate and explain various cryptographic algorithms in an accessible manner. This project serves as both an educational tool and a practical implementation of fundamental cryptographic concepts.

In today's digital world, cryptography forms the backbone of secure communications, data protection, and privacy. Understanding how these algorithms work is essential for anyone working in cybersecurity, software development, or information technology. Kryptos aims to bridge the gap between theoretical knowledge and practical application by providing a hands-on platform to experiment with cryptographic algorithms in real-time.

## Project Objectives

1. **Educational Enhancement**: Create an intuitive platform that demonstrates cryptographic algorithms in action, making abstract concepts concrete and understandable.

2. **Practical Implementation**: Develop working implementations of both classical and modern cryptographic techniques that can process text and file inputs.

3. **Visual Demonstration**: Provide step-by-step visualization of how cryptographic processes transform data, enhancing comprehension of the underlying mathematics.

4. **Security Awareness**: Highlight the strengths and limitations of different cryptographic approaches to foster better security practices.

## Application Architecture and UI

Kryptos is built using a Flask backend with a modern, responsive frontend. The architecture follows a Model-View-Controller pattern:

- **Backend (Controller)**: Python Flask handles routing, form processing, and integrates with cryptographic libraries
- **Frontend (View)**: HTML templates with Tailwind CSS and JavaScript provide a responsive, terminal-inspired interface
- **Utility Layer (Model)**: Custom cryptographic implementations and wrappers around standard libraries

The UI design draws inspiration from cybersecurity aesthetics with a dark terminal theme, matrix-like animations, and monospaced fonts. This choice serves both practical and thematic purposes:

- Creates an immersive hacker/security professional atmosphere
- Ensures code and cryptographic outputs are clearly readable
- Provides visual consistency across different cryptographic tools
- Implements dark mode by default to reduce eye strain when reading cryptographic outputs

## Implemented Cryptographic Algorithms

### 1. XOR Cipher

**Type**: Symmetric Key Cipher  
**Brief History**: One of the oldest and simplest ciphers, XOR has been used since the early days of computing and forms the basis of many stream ciphers.

**How It Works**: The XOR cipher performs a bitwise XOR operation between each byte of the plaintext and the corresponding byte of the key. If the key is shorter than the plaintext, it wraps around (repeats).

```
For each byte in plaintext:
    output_byte = plaintext_byte XOR key_byte_at_current_position
    position = (position + 1) % key_length
```

**Libraries Used**: Python's built-in operators for XOR operations  
**Integration**: Applied to both text input and file uploads, with detailed visualization of the byte-level XOR operations for educational purposes.

### 2. Caesar Cipher

**Type**: Symmetric Key Cipher (Classical)  
**Brief History**: One of the earliest known encryption techniques, used by Julius Caesar to communicate with his generals.

**How It Works**: Each character in the plaintext is shifted a certain number of places down the alphabet. For byte-level implementation, we operate on the byte values (0-255):

```
For each byte in plaintext:
    if operation is "encrypt":
        output_byte = (plaintext_byte + shift) % 256
    else: # decrypt
        output_byte = (plaintext_byte - shift) % 256
```

**Libraries Used**: Python's standard library  
**Integration**: Supports both single and multiple shift values that can be applied sequentially for polyalphabetic encryption. Works on both text and files.

### 3. Block Cipher (XOR-based)

**Type**: Symmetric Block Cipher  
**Brief History**: Block ciphers form the foundation of modern symmetric encryption, with XOR being a fundamental operation in many block cipher designs.

**How It Works**: Data is processed in fixed-size blocks, with each block XORed with the key. Various padding schemes ensure the last block is completely filled:

```
1. Divide input into fixed-size blocks
2. Apply padding to the last block if needed
3. For each block:
   - XOR the entire block with the key
4. Concatenate the processed blocks
```

**Libraries Used**: Python's built-in functionality  
**Integration**: Allows selection of different block sizes and padding modes, with an option to view detailed processing steps.

### 4. Diffie-Hellman Key Exchange

**Type**: Key Exchange Protocol  
**Brief History**: Developed by Whitfield Diffie and Martin Hellman in 1976, it was the first published public key exchange method.

**How It Works**: Allows two parties to establish a shared secret over an insecure channel:

```
1. Both parties agree on public parameters: prime p and base g
2. Each party generates a private key (a, b)
3. Each party calculates a public key:
   - A = g^a mod p
   - B = g^b mod p
4. Both parties exchange public keys
5. Each party calculates the shared secret:
   - Party 1: S = B^a mod p
   - Party 2: S = A^b mod p
6. Both parties now have the same shared secret S
```

**Libraries Used**: Python's built-in `pow()` function for modular exponentiation  
**Integration**: Interactive simulation of key exchange and secure messaging using the derived shared secret.

### 5. RSA Cipher

**Type**: Asymmetric Encryption  
**Brief History**: Developed in 1977 by Rivest, Shamir, and Adleman (hence RSA), it was one of the first practical asymmetric cryptosystems.

**How It Works**: Uses the mathematical properties of prime numbers to create a trapdoor function:

```
Key Generation:
1. Choose two large prime numbers p and q
2. Calculate n = p × q
3. Calculate φ(n) = (p-1) × (q-1)
4. Choose e where 1 < e < φ(n) and gcd(e, φ(n)) = 1
5. Calculate d where (d × e) mod φ(n) = 1

Encryption:
- c = m^e mod n (where m is the message and c is the ciphertext)

Decryption:
- m = c^d mod n
```

**Libraries Used**: Python's `math.gcd` and custom implementations of modular inverse  
**Integration**: Complete key generation, encryption, and decryption functionality with option to download key pairs.

### 6. ECC Secure Messenger (ECIES)

**Type**: Asymmetric Encryption with Hybrid Encryption  
**Brief History**: Elliptic Curve Cryptography was introduced in the mid-1980s and has gained popularity due to its efficiency with smaller key sizes.

**How It Works**: Combines elliptic curve Diffie-Hellman with symmetric encryption:

```
Encryption:
1. Generate ephemeral EC key pair
2. Derive shared secret using recipient's public key
3. Use key derivation function to create symmetric key
4. Encrypt message with symmetric key (AES-GCM)
5. Send ephemeral public key, IV, tag, and ciphertext

Decryption:
1. Compute shared secret using recipient's private key and sender's ephemeral public key
2. Derive symmetric key
3. Use AES-GCM to decrypt with IV and tag
```

**Libraries Used**: Python's `cryptography` library for EC operations and AES-GCM  
**Integration**: Secure messaging system with full PEM key format support.

### 7. Hash Functions

**Type**: One-way Functions  
**Brief History**: Cryptographic hashes emerged in the 1970s with MD algorithms, followed by SHA families developed by the NSA.

**How It Works**: Hash functions take arbitrary input and produce a fixed-size output:

```
1. Process input data through a complex mathematical algorithm
2. Output a fixed-length hash value (digest)
3. Even small changes to input produce vastly different outputs
```

**Libraries Used**: Python's `hashlib` module  
**Integration**: Support for multiple hash algorithms (MD5, SHA-1, SHA-256, SHA-512) with both text and file processing capabilities.

## Sample Outputs

### XOR Cipher

![XOR Cipher](https://github.com/s0y4hh/Applied-Cryptography-FP/blob/main/screenshots/xor.png?raw=true)

### Caesar Cipher

![Caesar Cipher](https://github.com/s0y4hh/Applied-Cryptography-FP/blob/main/screenshots/caesar.png?raw=true)

### Block Cipher

![Block Cipher](https://github.com/s0y4hh/Applied-Cryptography-FP/blob/main/screenshots/block.png?raw=true)

### Diffie-Hellman Key Exchange

![Diffie-Hellman](https://github.com/s0y4hh/Applied-Cryptography-FP/blob/main/screenshots/diffie-hellman.png?raw=true)

### RSA Cipher

![RSA Cipher](https://github.com/s0y4hh/Applied-Cryptography-FP/blob/main/screenshots/rsa.png?raw=true)

### ECC Secure Messenger

![ECC Secure Messenger](https://github.com/s0y4hh/Applied-Cryptography-FP/blob/main/screenshots/ecc.png?raw=true)

### Hash Functions

![Hash Functions](https://github.com/s0y4hh/Applied-Cryptography-FP/blob/main/screenshots/hash.png?raw=true)

## Installation and Setup

```bash
# Clone the repository
git clone https://github.com/s0y4hh/Applied-Cryptography-FP.git

# Navigate to project directory
cd Applied-Cryptography-FP

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install requirements
pip install -r requirements.txt

# Run the application
python app.py
```

The application will be available at `http://localhost:5000`.

## Technologies Used

- **Backend**: Python, Flask
- **Frontend**: HTML, CSS (Tailwind), JavaScript
- **Cryptography**: Python cryptography libraries, custom implementations

## Contributors

-
-
-
-

## License

MIT License
