import json
import socket
import threading
import os
import time

from typing import Dict, List

from crypto_utils import (
    sha256,
    verify_signature,
    bytes_to_public_key
)


class CentralServer:
    """
    Basit merkezi sunucu:
      - user_data: {
            username: {
                "user_id": bytes,
                "public_key": bytes,
                "online": bool,
                "messages": [(from_username, ciphertext_bytes), ...]
            }
        }
      - pending_challenges: {
            username: {
                "challenge": bytes,
                "timestamp": float
            }
        }
    """

    def __init__(self, host="127.0.0.1", port=5000, challenge_ttl=300):
        """
        :param challenge_ttl: Challenge'ların kaç saniye geçerli olacağı (örnek 300 = 5 dakika).
        """
        self.host = host
        self.port = port
        self.challenge_ttl = challenge_ttl  # saniye cinsinden
        self.user_data = {}
        self.pending_challenges = {}

    def start(self):
        """
        Sunucuyu TCP soket olarak başlatır,
        gelen bağlantıları kabul eder ve her istemci için handle_client'i ayrı thread'de çalıştırır.
        """
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind((self.host, self.port))
        server_sock.listen(5)
        print(f"[Server] Dinlemede: {self.host}:{self.port}")

        while True:
            client_sock, addr = server_sock.accept()
            print(f"[Server] Yeni bağlantı: {addr}")
            threading.Thread(target=self.handle_client, args=(client_sock,)).start()

    def handle_client(self, client_sock):
        """
        İstemciden gelen JSON komutlarını okuyup ilgili fonksiyonlara yönlendirir.
        Her komut öncesinde eski challenge'ları temizler (cleanup_old_challenges).
        """
        try:
            while True:
                data = self.recv_json(client_sock)
                if not data:
                    break

                # Her komut öncesi "eski" challenge'ları temizleyelim.
                self.cleanup_old_challenges()

                command = data.get("command")
                if command == "GET_REGISTER_CHALLENGE":
                    self.cmd_get_register_challenge(client_sock, data)
                elif command == "REGISTER":
                    self.cmd_register(client_sock, data)
                elif command == "GET_LOGIN_CHALLENGE":
                    self.cmd_get_login_challenge(client_sock, data)
                elif command == "LOGIN":
                    self.cmd_login(client_sock, data)
                elif command == "LOOKUP":
                    self.cmd_lookup(client_sock, data)
                elif command == "SEND_MSG":
                    self.cmd_send_msg(client_sock, data)
                elif command == "FETCH_MSGS":
                    self.cmd_fetch_msgs(client_sock, data)
                elif command == "LOGOUT":
                    self.cmd_logout(client_sock, data)
                else:
                    self.send_json(client_sock, {"status": "error", "error": "Unknown command"})
        except ConnectionResetError:
            pass
        finally:
            client_sock.close()

    # ---------------------------------------------------------------------
    #                 TEMİZLİK (CLEANUP) MEKANİZMASI
    # ---------------------------------------------------------------------
    def cleanup_old_challenges(self):
        """
        pending_challenges sözlüğündeki challenge'ların zamanına bakarak
        belirli bir TTL'yi aşanları siler.
        """
        now = time.time()
        to_delete = []
        for uname, data in self.pending_challenges.items():
            age = now - data["timestamp"]  # challenge ne kadar önce oluşturulmuş?
            if age > self.challenge_ttl:
                to_delete.append(uname)

        for uname in to_delete:
            print(f"[Server] Kullanılmamış challenge temizleniyor: {uname}")
            del self.pending_challenges[uname]

    # ------------- 1) Kayıt (Register) için challenge üretimi -------------

    def cmd_get_register_challenge(self, client_sock, data):
        """
        GET_REGISTER_CHALLENGE:
          data = { "command": "GET_REGISTER_CHALLENGE", "username": "Alice" }
        Dönen:
          { "status": "ok", "challenge": "...hex..." }

        - Sunucu, kayıt için rastgele 32 byte'lık bir challenge üretir,
          pending_challenges'e kaydeder ve kullanıcıya döndürür.
        - Eğer username zaten varsa hata döndürür.
        """
        username = data.get("username")
        if not username:
            self.send_json(client_sock, {"status": "error", "error": "Missing username"})
            return

        if username in self.user_data:
            self.send_json(client_sock, {"status": "error", "error": "Username already exists"})
            return

        challenge = os.urandom(32)
        self.pending_challenges[username] = {
            "challenge": challenge,
            "timestamp": time.time()
        }

        self.send_json(client_sock, {"status": "ok", "challenge": challenge.hex()})

    def cmd_register(self, client_sock, data):
        """
        REGISTER:
          data = {
            "command": "REGISTER",
            "username": "Alice",
            "challenge": "...",
            "signature": "...",
            "public_key": "..."
          }
        Dönen:
          { "status": "ok", "msg": "Registration successful" } veya hata

        - İstemci, 'GET_REGISTER_CHALLENGE' ile aldığı challenge'ı
          kendi private key'iyle imzalayıp buraya gönderir.
        - Sunucu challenge'ın doğru olduğunu, imzanın geçerli olduğunu doğrularsa
          user_data içine kaydeder.
        """
        username = data.get("username")
        challenge_hex = data.get("challenge")
        signature_hex = data.get("signature")
        pubkey_hex = data.get("public_key")

        if not (username and challenge_hex and signature_hex and pubkey_hex):
            self.send_json(client_sock, {"status": "error", "error": "Missing fields"})
            return

        if username in self.user_data:
            self.send_json(client_sock, {"status": "error", "error": "Username already registered"})
            return

        if username not in self.pending_challenges:
            self.send_json(client_sock, {
                "status": "error",
                "error": "No challenge found for this username (did you call GET_REGISTER_CHALLENGE first?)"
            })
            return

        stored_data = self.pending_challenges[username]
        stored_challenge = stored_data["challenge"]

        # Challenge eşleşiyor mu?
        if stored_challenge.hex() != challenge_hex:
            self.send_json(client_sock, {"status": "error", "error": "Challenge mismatch"})
            return

        # ECDSA doğrulaması
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        signature_bytes = bytes.fromhex(signature_hex)
        try:
            pubkey_obj = bytes_to_public_key(pubkey_bytes)
            if not verify_signature(pubkey_obj, signature_bytes, stored_challenge):
                self.send_json(client_sock, {"status": "error", "error": "Invalid signature"})
                return
        except Exception as e:
            self.send_json(client_sock, {"status": "error", "error": f"Signature verify error: {str(e)}"})
            return

        # Kayıt başarılı
        user_id = sha256(pubkey_bytes)
        self.user_data[username] = {
            "user_id": user_id,
            "public_key": pubkey_bytes,
            "online": False,
            "messages": []
        }
        # Kullanıldığı için pending'den silelim
        del self.pending_challenges[username]

        self.send_json(client_sock, {"status": "ok", "msg": "Registration successful"})

    # ------------- 2) Giriş (Login) için challenge üretimi -------------

    def cmd_get_login_challenge(self, client_sock, data):
        """
        GET_LOGIN_CHALLENGE:
          data = { "command": "GET_LOGIN_CHALLENGE", "username": "Alice" }
        Dönen:
          { "status": "ok", "challenge": "...hex..." }

        - Sunucu, giriş için rastgele 32 byte'lık bir challenge üretir,
          pending_challenges'e kaydeder ve kullanıcıya döndürür.
        - Eğer username yoksa "User not found" hatası döner.
        """
        username = data.get("username")
        if not username:
            self.send_json(client_sock, {"status": "error", "error": "Missing username"})
            return

        if username not in self.user_data:
            self.send_json(client_sock, {"status": "error", "error": "User not found"})
            return

        challenge = os.urandom(32)
        self.pending_challenges[username] = {
            "challenge": challenge,
            "timestamp": time.time()
        }

        self.send_json(client_sock, {"status": "ok", "challenge": challenge.hex()})

    def cmd_login(self, client_sock, data):
        """
        LOGIN:
          data = {
            "command": "LOGIN",
            "username": "Alice",
            "challenge": "...",
            "signature": "...",
            "public_key": "..."
          }
        Dönen:
          { "status": "ok", "msg": "Login successful." } veya hata

        - İstemci, 'GET_LOGIN_CHALLENGE' ile aldığı challenge'ı
          kendi private key'iyle imzalayıp buraya gönderir.
        - Sunucu challenge ve public_key kontrolü ile imzayı doğrularsa
          kullanıcıyı "online = True" yaparak giriş kabul eder.
        """
        username = data.get("username")
        challenge_hex = data.get("challenge")
        signature_hex = data.get("signature")
        pubkey_hex = data.get("public_key")

        if not (username and challenge_hex and signature_hex and pubkey_hex):
            self.send_json(client_sock, {"status": "error", "error": "Missing fields"})
            return

        if username not in self.user_data:
            self.send_json(client_sock, {"status": "error", "error": "User not found"})
            return

        if username not in self.pending_challenges:
            self.send_json(client_sock, {
                "status": "error",
                "error": "No login challenge found (did you call GET_LOGIN_CHALLENGE first?)"
            })
            return

        stored_data = self.pending_challenges[username]
        stored_challenge = stored_data["challenge"]

        if stored_challenge.hex() != challenge_hex:
            self.send_json(client_sock, {"status": "error", "error": "Challenge mismatch"})
            return

        user_rec = self.user_data[username]
        if user_rec["public_key"] != bytes.fromhex(pubkey_hex):
            self.send_json(client_sock, {"status": "error", "error": "Public key mismatch"})
            return

        # ECDSA doğrulaması
        try:
            pubkey_obj = bytes_to_public_key(user_rec["public_key"])
            signature_bytes = bytes.fromhex(signature_hex)
            if not verify_signature(pubkey_obj, signature_bytes, stored_challenge):
                self.send_json(client_sock, {"status": "error", "error": "Signature invalid"})
                return
        except Exception as e:
            self.send_json(client_sock, {"status": "error", "error": f"Signature verify error: {str(e)}"})
            return

        # Başarılı giriş
        user_rec["online"] = True
        del self.pending_challenges[username]

        self.send_json(client_sock, {"status": "ok", "msg": "Login successful."})

    # ------------- LOOKUP, SEND_MSG, FETCH_MSGS, LOGOUT -------------

    def cmd_lookup(self, client_sock, data):
        """
        LOOKUP:
          data = { "command": "LOOKUP", "username": "Bob" }
        Dönen:
          { "status": "ok", "public_key": "...hex..." } veya hata

        - İstemci, bu komutla hedef kullanıcı (Bob) için sunucudan public key bilgisini alır.
        """
        target_user = data.get("username")
        if not target_user or target_user not in self.user_data:
            self.send_json(client_sock, {"status": "error", "error": "User not found"})
            return

        pubkey_hex = self.user_data[target_user]["public_key"].hex()
        self.send_json(client_sock, {"status": "ok", "public_key": pubkey_hex})

    def cmd_send_msg(self, client_sock, data):
        """
        SEND_MSG:
          data: {
            "command": "SEND_MSG",
            "from_user": "...",
            "to_user": "...",
            "ciphertext_hex": "..."
          }
        Dönen:
          { "status": "ok" } veya hata

        - İstemci, gönderilecek şifreli mesajı sunucuya iletir.
        - Sunucu bu mesajı 'to_user' kullanıcısının messages listesine ekler.
        """
        from_user = data.get("from_user")
        to_user = data.get("to_user")
        ciphertext_hex = data.get("ciphertext_hex")

        if not (from_user and to_user and ciphertext_hex):
            self.send_json(client_sock, {"status": "error", "error": "Missing fields"})
            return

        if to_user not in self.user_data:
            self.send_json(client_sock, {"status": "error", "error": "Target user not found"})
            return

        self.user_data[to_user]["messages"].append((from_user, bytes.fromhex(ciphertext_hex)))
        print(f"[Server] Mesaj kuyruklandı: {from_user} -> {to_user}")
        self.send_json(client_sock, {"status": "ok"})

    def cmd_fetch_msgs(self, client_sock, data):
        """
        FETCH_MSGS:
          data: { "command": "FETCH_MSGS", "username": "Alice" }
        Dönen:
          {
            "status": "ok",
            "messages": [
              { "from": "...", "ciphertext_hex": "..." },
              ...
            ]
          }

        - Sunucu, "username" için birikmiş bütün mesajları döndürür.
        - Döndürdükten sonra bu mesajları sunucu tarafında siler (queue mantığı).
        """
        username = data.get("username")
        if not username or username not in self.user_data:
            self.send_json(client_sock, {"status": "error", "error": "User not found"})
            return

        msgs = self.user_data[username]["messages"]
        out = []
        for (frm, ciph) in msgs:
            out.append({"from": frm, "ciphertext_hex": ciph.hex()})

        self.user_data[username]["messages"] = []  # temizle
        self.send_json(client_sock, {"status": "ok", "messages": out})

    def cmd_logout(self, client_sock, data):
        """
        LOGOUT:
          data: { "command": "LOGOUT", "username": "Alice" }
        Dönen:
          { "status": "ok", "msg": "Logged out" }

        - Kullanıcı online durumunu false yapar, oturumu kapatır.
        """
        username = data.get("username")
        if username in self.user_data:
            self.user_data[username]["online"] = False

        self.send_json(client_sock, {"status": "ok", "msg": "Logged out"})

    # ------------- Yardımcı fonksiyonlar -----------------
    def send_json(self, client_sock, obj: dict):
        text = json.dumps(obj).encode('utf-8')
        length_prefix = len(text).to_bytes(4, 'big')
        client_sock.sendall(length_prefix + text)

    def recv_json(self, client_sock):
        length_data = self._recv_exact(client_sock, 4)
        if not length_data:
            return None
        length = int.from_bytes(length_data, 'big')
        body = self._recv_exact(client_sock, length)
        if not body:
            return None
        return json.loads(body.decode('utf-8'))

    def _recv_exact(self, sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf


if __name__ == "__main__":
    # challenge_ttl=300 -> 5 dakika içinde kullanılmazsa challenge silinecektir.
    server = CentralServer(host="127.0.0.1", port=5000, challenge_ttl=300)
    server.start()
