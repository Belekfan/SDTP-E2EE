import argparse
import json
import socket
import sys
import secrets

from crypto_utils import (
    generate_ec_keypair,
    public_key_to_bytes,
    bytes_to_public_key,
    sign_data,
    verify_signature,
    sha256,
    derive_shared_key,
    aes_gcm_encrypt,
    aes_gcm_decrypt
)


def send_json(sock, obj: dict):
    data = json.dumps(obj).encode('utf-8')
    length_prefix = len(data).to_bytes(4, 'big')
    sock.sendall(length_prefix + data)


def recv_json(sock):
    length_data = recv_exact(sock, 4)
    if not length_data:
        return None
    length = int.from_bytes(length_data, 'big')
    body = recv_exact(sock, length)
    if not body:
        return None
    return json.loads(body.decode('utf-8'))


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


class Client:
    def __init__(self, username: str, server_host="127.0.0.1", server_port=5000):
        self.username = username
        self.server_host = server_host
        self.server_port = server_port

        # ECC anahtar çifti
        self.private_key, self.public_key = generate_ec_keypair()
        self.public_key_bytes = public_key_to_bytes(self.public_key)
        self.user_id = sha256(self.public_key_bytes)

        # Sunucuya TCP bağlantısı
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server_host, self.server_port))

        print(f"[Client] Bağlandı: {self.server_host}:{self.server_port}")

    # ------------------ Register / Login için Challenge-Response ------------------
    def get_register_challenge(self):
        """
        Sunucudan 'REGISTER' için challenge alır (GET_REGISTER_CHALLENGE)
        """
        req = {
            "command": "GET_REGISTER_CHALLENGE",
            "username": self.username
        }
        send_json(self.sock, req)
        resp = recv_json(self.sock)
        return resp

    def register_user(self, challenge_hex):
        """
        Sunucudan gelen challenge_hex'i private key ile imzalayıp
        REGISTER isteği gönderir.
        """
        challenge_bytes = bytes.fromhex(challenge_hex)
        signature = sign_data(self.private_key, challenge_bytes)

        req = {
            "command": "REGISTER",
            "username": self.username,
            "challenge": challenge_hex,
            "signature": signature.hex(),
            "public_key": self.public_key_bytes.hex()
        }
        send_json(self.sock, req)
        resp = recv_json(self.sock)
        return resp

    def get_login_challenge(self):
        req = {
            "command": "GET_LOGIN_CHALLENGE",
            "username": self.username
        }
        send_json(self.sock, req)
        resp = recv_json(self.sock)
        return resp

    def login_user(self, challenge_hex):
        """
        Sunucudan gelen challenge_hex'i private key ile imzalayıp
        LOGIN isteği gönderir.
        """
        challenge_bytes = bytes.fromhex(challenge_hex)
        signature = sign_data(self.private_key, challenge_bytes)

        req = {
            "command": "LOGIN",
            "username": self.username,
            "challenge": challenge_hex,
            "signature": signature.hex(),
            "public_key": self.public_key_bytes.hex()
        }
        send_json(self.sock, req)
        resp = recv_json(self.sock)
        return resp

    # ------------------ Kullanıcı İşlemleri ------------------
    def lookup_user(self, target_username) -> bytes:
        """
        Sunucudan 'target_username' kullanıcısının public key'ini al.
        """
        req = {
            "command": "LOOKUP",
            "username": target_username
        }
        send_json(self.sock, req)
        resp = recv_json(self.sock)
        if resp and resp.get("status") == "ok":
            return bytes.fromhex(resp["public_key"])
        else:
            print("[Client] LOOKUP hatası:", resp)
            return None

    def send_message(self, to_user: str, message_text: str):
        """
        'to_user'a ephemeral ECDH + AES-GCM ile şifreli mesaj gönderir.
        """
        # 1) to_user'ın public key'ini al
        peer_pub_bytes = self.lookup_user(to_user)
        if not peer_pub_bytes:
            print("[Client] Kullanıcı bulunamadı veya hata.")
            return

        # 2) Ephemeral key çifti
        eph_priv, eph_pub = generate_ec_keypair()
        eph_pub_bytes = public_key_to_bytes(eph_pub)

        # 3) Session key türet (eph_priv X peer_pub)
        peer_pub_key_obj = bytes_to_public_key(peer_pub_bytes)
        session_key = derive_shared_key(eph_priv, peer_pub_key_obj)

        # 4) message_text -> AES-GCM ile şifrele
        nonce, ct = aes_gcm_encrypt(session_key, message_text.encode('utf-8'))

        # Mesaj formatı: [ephemeralPubKey(65 bytes) + nonce(12 bytes) + ciphertext+tag]
        packet = eph_pub_bytes + nonce + ct

        req = {
            "command": "SEND_MSG",
            "from_user": self.username,
            "to_user": to_user,
            "ciphertext_hex": packet.hex()
        }
        send_json(self.sock, req)
        resp = recv_json(self.sock)
        if resp:
            print("[Client] SEND_MSG yanıt:", resp.get("status"), resp.get("error", ""))

    def fetch_messages(self):
        """
        Sunucudan bekleyen mesajları al, ephemeral ECDH ile deşifre et ve ekrana yaz.
        """
        req = {
            "command": "FETCH_MSGS",
            "username": self.username
        }
        send_json(self.sock, req)
        resp = recv_json(self.sock)
        if not resp or resp.get("status") != "ok":
            print("[Client] FETCH_MSGS hata:", resp)
            return

        messages = resp["messages"]  # list of { from, ciphertext_hex }
        if not messages:
            print("[Client] Mesaj yok.")
            return

        for msg in messages:
            from_user = msg["from"]
            enc_hex = msg["ciphertext_hex"]
            enc_data = bytes.fromhex(enc_hex)

            # enc_data = [ eph_pub (65) + nonce (12) + ct+tag (?) ]
            eph_len = 65
            if len(enc_data) < eph_len + 12 + 16:
                print("[Client] Şifreli veri çok kısa, atlanıyor.")
                continue

            eph_pub_bytes = enc_data[:eph_len]
            nonce = enc_data[eph_len:eph_len+12]
            ct_tag = enc_data[eph_len+12:]

            # ECDH -> ephemeral pub key ile kendi (static) private key
            eph_pub_obj = bytes_to_public_key(eph_pub_bytes)
            session_key = derive_shared_key(self.private_key, eph_pub_obj)

            try:
                plaintext = aes_gcm_decrypt(session_key, nonce, ct_tag)
                print(f"\n[Client] Yeni Mesaj! Kimden: {from_user}\n => {plaintext.decode('utf-8')}\n")
            except Exception as e:
                print("[Client] Deşifre hatası:", e)

    def logout(self):
        req = {
            "command": "LOGOUT",
            "username": self.username
        }
        send_json(self.sock, req)
        _ = recv_json(self.sock)
        self.sock.close()
        print("[Client] Bağlantı kapatıldı.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", required=True, help="Kullanıcı adınız")
    args = parser.parse_args()

    client = Client(args.username)

    # 1) GET_REGISTER_CHALLENGE iste
    resp_ch = client.get_register_challenge()
    if not resp_ch or resp_ch.get("status") != "ok":
        print("[Client] Challenge alamadık:", resp_ch)
        sys.exit(1)

    # 2) REGISTER
    challenge_hex = resp_ch["challenge"]
    resp_reg = client.register_user(challenge_hex)
    if not resp_reg or resp_reg.get("status") != "ok":
        print("[Client] Register hata:", resp_reg)
        sys.exit(1)
    print("[Client] Kayıt başarılı!")

    # 3) GET_LOGIN_CHALLENGE
    resp_login_ch = client.get_login_challenge()
    if not resp_login_ch or resp_login_ch.get("status") != "ok":
        print("[Client] Login challenge alamadık:", resp_login_ch)
        sys.exit(1)

    # 4) LOGIN
    login_ch_hex = resp_login_ch["challenge"]
    resp_login = client.login_user(login_ch_hex)
    if not resp_login or resp_login.get("status") != "ok":
        print("[Client] Login başarısız:", resp_login)
        sys.exit(1)
    print("[Client] Login başarılı!")

    # Artık komut döngüsü vb.
    print("[Client] Komutlar: LOOKUP <user>, SEND <user> <msg>, FETCH, EXIT\n")

    while True:
        line = input(">> ").strip()
        if not line:
            continue

        parts = line.split(" ", 2)
        cmd = parts[0].upper()

        if cmd == "LOOKUP":
            if len(parts) < 2:
                print("Kullanım: LOOKUP <username>")
                continue
            target_user = parts[1]
            pk = client.lookup_user(target_user)
            if pk:
                print(f"[Client] {target_user} public_key (hex) = {pk.hex()[:16]}...")
        elif cmd == "SEND":
            if len(parts) < 3:
                print("Kullanım: SEND <username> <message>")
                continue
            to_user = parts[1]
            message_text = parts[2]
            client.send_message(to_user, message_text)
        elif cmd == "FETCH":
            client.fetch_messages()
        elif cmd == "EXIT":
            client.logout()
            break
        else:
            print("Bilinmeyen komut")


if __name__ == "__main__":
    main()
