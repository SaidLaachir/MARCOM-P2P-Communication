MARCOM – Secure Peer-to-Peer Communication Application

Overview
MARCOM is a secure peer-to-peer (P2P) communication application developed in Python.
It demonstrates the practical implementation of modern cryptographic protocols combined with a graphical user interface, enabling two parties (client and server) to exchange messages securely over a network.

The project is designed with an educational and demonstrative objective, focusing on:
Secure key exchange
Confidentiality
Integrity
Authentication
Clear visualization of cryptographic operations


Key Features
Peer-to-peer client/server architecture
Secure channel establishment using hybrid cryptography
Message confidentiality using symmetric encryption
Message integrity and authentication using digital signatures
Graphical interface for interaction and live visualization
Executable Windows application (no Python required at runtime)


Cryptographic Design
The application uses a hybrid cryptographic model, combining asymmetric and symmetric cryptography to ensure both security and performance.

1. ElGamal – Secure Key Exchange
The server generates an ElGamal key pair.
The client encrypts a randomly generated AES-256 key using the server’s ElGamal public key.
The encrypted AES key is securely transmitted to the server.
Both parties now share the same symmetric key.

2. AES-256-GCM – Message Confidentiality
All messages are encrypted using AES-256 in GCM mode.
Provides confidentiality and integrity through authenticated encryption.
Ensures high performance for real-time communication.

3. SHA-256 – Message Hashing
Each plaintext message is hashed using SHA-256.
The hash is used during the signature process to ensure integrity.

4. DSS (DSA) – Digital Signatures
Both client and server generate DSS key pairs.
Every message is digitally signed before transmission.
The receiver verifies the signature to ensure message integrity, sender authenticity, and protection against tampering.


Architecture Overview

server.py
Handles incoming connections, generates ElGamal and DSS keys, decrypts AES key, receives and verifies encrypted messages.

client.py
Connects to the server, generates DSS keys, encrypts and sends AES key, sends signed and encrypted messages.

gui_app.py
CustomTkinter-based graphical interface, centralized display of logs and cryptographic steps, colored visualization for each cryptographic phase, user interaction (connect, send messages, stop connection).

tools/
Cryptographic utility modules: AES-GCM implementation, ElGamal key generation and encryption, DSS signature handling.


Threading Model
Network operations (server/client) run in separate threads.
The GUI runs on the main thread.
Message reception is handled asynchronously.
Prevents interface freezing and ensures smooth interaction.


GUI Design and Visualization
The graphical interface provides role selection (Server / Client), connection management, message input and display, and a centralized console with ANSI color removal and logical color coding per cryptographic phase (Network events, Key exchange, ElGamal operations, AES encryption, SHA-256 hashing, DSS signatures).
This design is optimized for live demonstrations and academic presentations.


Executable Version
The application can be compiled into a standalone Windows executable using PyInstaller.

Build Command:
pyinstaller --onefile --windowed --name MARCOM --icon=icon.ico gui_app.py

MADE BY SAID LAACHIR AND SALMANE TOUBI THE 29TH DECEMBER OF 2025
