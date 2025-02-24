import os
import socket
import threading
import json
from cryptography.fernet import Fernet

# Hardcoded encryption key (both server and client must share the same key)
ENCRYPTION_KEY = b'V1StGXR8_Z5jdHi6B-myT0F7kJJ0wLgF3g5CfaFBWdw='
cipher = Fernet(ENCRYPTION_KEY)

PORT = 5000
CREDENTIALS_FILE = "users.txt"

# Bind to all interfaces
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('', PORT))

# Get the server's IP address and print it
server_ip = socket.gethostbyname(socket.gethostname())
print(f"Server running on {server_ip}:{PORT}")

server.listen()


# ---------- Credential Persistence Functions ----------

def load_user_db():
    """Load the user database from a file.
       Each line in the file is in the format: username:encrypted_password
    """
    user_db = {}
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        username, encrypted_password = line.split(":", 1)
                        user_db[username] = encrypted_password
                    except Exception as e:
                        print("Error parsing line:", line, e)
    return user_db


def save_user_credentials(username, password):
    """Encrypt the password and append the new user to the credentials file."""
    encrypted_password = cipher.encrypt(password.encode('utf-8')).decode('utf-8')
    with open(CREDENTIALS_FILE, "a") as f:
        f.write(f"{username}:{encrypted_password}\n")
    return encrypted_password


# Load the credentials at startup
user_db = load_user_db()

# ---------- End Credential Persistence ----------

# Dictionaries to track client info and channel memberships.
clients = {}  # client_socket: {"username": str, "channel": str}
channels = {"general": []}  # channel_name: list of client sockets


def update_online_users():
    """Broadcast the current online user list to all connected clients."""
    online_users = [info["username"] for info in clients.values()]
    update_message = "/update_users " + ",".join(online_users)
    for client in list(clients.keys()):
        try:
            client.send(cipher.encrypt(update_message.encode('utf-8')))
        except Exception as e:
            remove_client(client)


def broadcast(message, channel="general"):
    """
    Send a message to all clients in a given channel.
    This version sends the message to every client (including the sender).
    """
    for client in channels.get(channel, []):
        try:
            client.send(cipher.encrypt(message.encode('utf-8')))
        except Exception as e:
            remove_client(client)


def remove_client(client):
    """Cleanly remove a client from all records."""
    if client in clients:
        channel = clients[client]["channel"]
        if client in channels.get(channel, []):
            channels[channel].remove(client)
        del clients[client]
    client.close()
    update_online_users()


def handle(client):
    try:
        # --- Authentication ---
        client.send(cipher.encrypt("LOGIN".encode('utf-8')))
        encrypted_data = client.recv(4096)
        data = cipher.decrypt(encrypted_data).decode('utf-8')
        auth_info = json.loads(data)
        action = auth_info.get("action")
        username = auth_info.get("username")
        password = auth_info.get("password")

        if action == "login":
            if username in user_db:
                stored_encrypted_password = user_db[username]
                try:
                    decrypted_password = cipher.decrypt(stored_encrypted_password.encode('utf-8')).decode('utf-8')
                except Exception as e:
                    client.send(cipher.encrypt("LOGIN_FAILED".encode('utf-8')))
                    client.close()
                    return
                if decrypted_password == password:
                    client.send(cipher.encrypt("LOGIN_SUCCESS".encode('utf-8')))
                else:
                    client.send(cipher.encrypt("LOGIN_FAILED".encode('utf-8')))
                    client.close()
                    return
            else:
                client.send(cipher.encrypt("LOGIN_FAILED".encode('utf-8')))
                client.close()
                return
        elif action == "signup":
            if username in user_db:
                client.send(cipher.encrypt("USER_EXISTS".encode('utf-8')))
                client.close()
                return
            else:
                encrypted_pw = save_user_credentials(username, password)
                user_db[username] = encrypted_pw
                client.send(cipher.encrypt("SIGNUP_SUCCESS".encode('utf-8')))
        else:
            client.send(cipher.encrypt("INVALID_ACTION".encode('utf-8')))
            client.close()
            return

        # --- Setup after authentication ---
        clients[client] = {"username": username, "channel": "general"}
        channels["general"].append(client)
        broadcast(f"{username} has joined the channel.", "general")
        update_online_users()

        # --- Main loop to handle messages ---
        while True:
            encrypted_message = client.recv(4096)
            if not encrypted_message:
                break
            try:
                message = cipher.decrypt(encrypted_message).decode('utf-8')
                # Process the /private command; any other message is treated as normal chat.
                if message.startswith("/private"):
                    parts = message.split(" ", 2)
                    if len(parts) >= 3:
                        target_username = parts[1].strip()
                        private_message = parts[2].strip()
                        target_client = None
                        for c, info in clients.items():
                            if info["username"] == target_username:
                                target_client = c
                                break
                        if target_client:
                            target_client.send(cipher.encrypt(
                                f"Private from {clients[client]['username']}: {private_message}".encode('utf-8')))
                            client.send(
                                cipher.encrypt(f"Private to {target_username}: {private_message}".encode('utf-8')))
                        else:
                            client.send(cipher.encrypt("User not found.".encode('utf-8')))
                    else:
                        client.send(cipher.encrypt("Usage: /private <username> <message>".encode('utf-8')))
                else:
                    # Treat any other message as a normal chat message.
                    user = clients[client]["username"]
                    broadcast(f"{user}: {message}", clients[client]["channel"])
            except Exception as e:
                print("Error handling message:", e)
                break
    except Exception as e:
        print("Authentication error:", e)
    finally:
        if client in clients:
            channel = clients[client]["channel"]
            username = clients[client]["username"]
            remove_client(client)
            broadcast(f"{username} has left the channel.", channel)


def receive():
    print("Waiting for connections...")
    while True:
        client, address = server.accept()
        print(f"Connected with {address}")
        thread = threading.Thread(target=handle, args=(client,))
        thread.start()


if __name__ == "__main__":
    receive()
