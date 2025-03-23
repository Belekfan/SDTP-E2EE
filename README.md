# SDTP-E2EE
Secure Data Transfer Protocol

---

# 1. Overview

This protocol provides:

1. **Central Server**  
   - Manages user registration and login.  
   - Stores each user’s `publicKey`.  
   - Queues encrypted messages and delivers them to the correct recipient (without decrypting the message contents).

2. **Client**  
   - Generates a **private/public key** pair.  
   - The identity is calculated as: `userID = SHA-256(publicKey)`  
   - Registers with the server by sending its `publicKey`.  
   - Communicates with other clients using **ephemeral ECDH + AES-GCM** to establish end-to-end encrypted communication.  
   - Only the intended recipient can decrypt the message content.

3. **Goal**  
   - Ensure that all messages are encrypted **end-to-end**, even the server cannot read them.  
   - Use `SHA-256(publicKey)` as the user identity instead of IP addresses.  
   - Provide lightweight registration and identity discovery.

> **Note**: This protocol is designed as a **proof of concept**. For production environments, additional security mechanisms, error handling, NAT traversal, certificate infrastructure, and other requirements must be addressed.

---

# 2. Components & File Structure

Example file structure:

```
.
├── crypto_utils.py        # Cryptographic utilities (ECDH, AES-GCM, etc.)
├── server.py              # Central server logic
├── client.py              # Interactive client logic
├── requirements.txt       # Python dependencies (e.g., cryptography>=39.0.0)
└── Dockerfile (optional)  # For Docker container support
```

## 2.1 Requirements

- **Python 3.7+**
- **pip** (Python package manager)
- `cryptography` library (Install via `pip install -r requirements.txt`)
- Optional: Docker (for containerization)

---

# 3. Installation

1. **Clone or copy the project code**  
   Place all project files into a working directory (e.g., `e2ee-protocol/`).

2. **Install dependencies**  
   ```bash
   pip install -r requirements.txt
   ```

3. **Start the server**  
   ```bash
   python server.py
   ```
   - By default, the server listens on `127.0.0.1:5000`.  
   - You should see a message like `[Server] Listening on 127.0.0.1:5000`.

4. **Run the client**  
   ```bash
   python client.py --username <YOUR_NAME>
   ```
   - The client connects to the server and tries to register.  
   - If already registered, it logs in and enters an interactive prompt for commands.

**Note**: It's recommended to run the server and client in separate terminals. If you wish to change server IP/port, you may modify constants in the scripts.

---

# 4. Client Commands

Once the client starts, it presents an interactive shell. Supported commands:

1. **LOOKUP <username>**  
   - Retrieves the `publicKey` of the given `<username>` from the server.  
   - This is used to perform ECDH key exchange when sending a message.

2. **SEND <username> <message>**  
   - Encrypts `<message>` using ECDH + AES-GCM and sends it to `<username>` via the server.  
   - The server queues the encrypted payload for the recipient.

3. **FETCH**  
   - Requests all queued messages from the server.  
   - Each message contains:  
     `[ephemeralPublicKey (65 bytes)] + [nonce (12 bytes)] + [ciphertext + tag]`  
   - The client extracts the ephemeral public key and derives a shared session key.  
   - It decrypts the content using AES-GCM and displays it.

4. **EXIT**  
   - Sends a "LOGOUT" request to the server and terminates the session.

### 4.1 Example Messaging Flow

Assuming Alice and Bob are both connected:

- In Alice's terminal:  
  ```
  >> SEND Bob Hello Bob, how are you?
  ```
- In Bob's terminal:  
  ```
  >> FETCH
  ```
  Bob sees the decrypted message. He can respond:  
  ```
  >> SEND Alice I'm good, how about you?
  ```
- Back in Alice's terminal:  
  ```
  >> FETCH
  ```
  She sees Bob's reply.

---

# 5. Running via Docker (Optional)

1. **Build Docker image** (if Dockerfile is present):  
   ```bash
   docker build -t my_e2ee_app:latest .
   ```

2. **Run the server in a container**:  
   ```bash
   docker run -d -p 5000:5000 --name e2ee_server my_e2ee_app:latest
   ```

3. **Run client**  
   - From another terminal or machine:  
     ```bash
     python client.py --username Alice
     ```

   You can adjust host and port in the script if the server is remote or not using default settings.

---

# 6. Security & Configuration Notes

- **Private Key Storage**:  
  The demo client generates a new key pair each run. You may persist private keys securely if needed.

- **Signature Verification**:  
  During registration/login, the server expects a challenge signed with the client's private key. Full ECDSA verification should be implemented in production.

- **Deployment Notes**:  
  - Behind NAT/firewall? Ensure TCP port 5000 is open and routed properly.  
  - For large-scale use, implement persistent storage (e.g., a database) on the server.  
  - Delivery of queued messages and offline client handling may require additional logic.

- **Forward Secrecy**:  
  The demo uses basic ephemeral ECDH. For advanced setups (e.g., Signal Protocol), implement a ratcheting mechanism.

---

# 7. Troubleshooting

1. **Connection Refused**  
   - Make sure `server.py` is running and listening on the expected IP/port.  
   - Check firewall or SELinux restrictions.

2. **Message Not Received**  
   - Ensure the receiving user runs `FETCH`.  
   - Confirm correct username spelling.

3. **Decryption Failure / Invalid Tag**  
   - May occur if message structure is malformed.  
   - Check ephemeral key, nonce, ciphertext lengths, and offsets.

4. **Missing Dependencies**  
   - Run:  
     ```bash
     pip install -r requirements.txt
     ```

---

---

# 8. Further Development Ideas

The following features can be added to improve security, scalability, and usability:

1. **Cisco IOx Deployment**  
   - Docker support and IOx tools like `ioxclient` can be added to package and deploy the application on Cisco IOx-enabled routers or switches.

2. **Group Messaging**  
   - Group chat functionality can be added by implementing shared group key management or using per-recipient encryption for secure multi-user communication.

3. **Message Signatures**  
   - ECDSA signatures can be added to each message to verify the authenticity of the sender and ensure message integrity.

4. **Persistent Identity**  
   - Secure ECC private key storage (e.g., encrypted JSON or secure keystore) can be added to maintain a consistent identity across sessions.

5. **UI Development**  
   - A user interface can be added to improve the user experience, either as a web frontend using Flask or a desktop GUI using PyQt.

---

# 9. Conclusion

This documentation guides you through using a custom end-to-end encrypted communication protocol based on:

- Central server coordination  
- SHA-256(publicKey) identity  
- Ephemeral ECDH key exchange  
- AES-GCM message encryption  

You can test securely encrypted messaging between clients and optionally containerize and deploy the system to a Cisco device using IOx.

For production use, you should extend the system with robust authentication, logging, error handling, and advanced encryption mechanisms.

---

SDTP-E2EE --Developed integrated with Chatgpt-o1
