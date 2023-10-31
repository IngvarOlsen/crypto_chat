import argparse
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, Box

skserver = PrivateKey.generate()
pkserver = skserver.public_key
server_public_key = pkserver.encode(encoder=nacl.encoding.HexEncoder)

def generate_shared_key(local_private_key, remote_public_key):
    """Generate a shared key using local private key and remote public key."""
    box = Box(local_private_key, remote_public_key)
    print('generate_shared_key box')
    print(box)
    return box.shared_key()

def encrypt_with_shared_secret(message, shared_secret):
    """Encrypt the given message using the provided shared secret."""
    box = nacl.secret.SecretBox(shared_secret)
    print('encrypt_with_shared_secret box')
    print(box)
    return box.encrypt(message)

def decrypt_with_shared_secret(encrypted_message, shared_secret):
    """Decrypt the given encrypted message using the provided shared secret."""
    box = nacl.secret.SecretBox(shared_secret)
    print('decrypt_with_shared_secret box')
    print(box)
    print('decrypt_with_shared_secret box decrypted')
    print(box.decrypt(encrypted_message))
    return box.decrypt(encrypted_message)

def accept_incoming_connections():
    """Sets up handling for incoming clients."""
    while True:
        client, client_address = SERVER.accept()
        print("%s:%s has connected." % client_address)
        
        # Send server's public key
        print('server_public_key')
        print(server_public_key)
        client.send(server_public_key)
        
        # Receive client's public key
        client_public_key_hex = client.recv(64).decode('utf-8')
        client_public_key = nacl.public.PublicKey(client_public_key_hex, encoder=nacl.encoding.HexEncoder)
        print('client_public_key')
        print(client_public_key)
        shared_secret = generate_shared_key(skserver, client_public_key)
        print('shared_secret')
        print(shared_secret)
        clients[client] = {'client_public_key': client_public_key, 'shared_secret': shared_secret}

        addresses[client] = client_address
        Thread(target=handle_client, args=(client,)).start()

def handle_client(client):
    """Handles a single client connection."""
    shared_secret = clients[client]['shared_secret']
    print('shared_secret')
    print(shared_secret)
    name_encrypted = client.recv(BUFSIZ)
    name = decrypt_with_shared_secret(name_encrypted, shared_secret).decode("utf8")
    print('name')
    print(name)
    welcome = 'Welcome %s! If you ever want to quit, type {quit} to exit.' % name
    client.send(encrypt_with_shared_secret(bytes(welcome, "utf8"), shared_secret))
    msg = "%s has joined the chat!" % name
    # broadcast(encrypt_with_shared_secret(bytes(msg, "utf8"), shared_secret), client)
    broadcast(bytes(msg, "utf8"), client)

    while True:
        encrypted_msg = client.recv(BUFSIZ)
        decrypted_msg = decrypt_with_shared_secret(encrypted_msg, shared_secret)

        if decrypted_msg != bytes("{quit}", "utf8"):
            #broadcast(encrypt_with_shared_secret(decrypted_msg, shared_secret), client)
            broadcast(decrypted_msg, client)
        else:
            client.send(encrypt_with_shared_secret(bytes("{quit}", "utf8"), shared_secret))
            client.close()
            del clients[client]
            #broadcast(encrypt_with_shared_secret(bytes("%s has left the chat." % name, "utf8"), shared_secret), client)
            broadcast(bytes("%s has left the chat." % name, "utf8"), shared_secret)
            break

# def broadcast(msg, from_client):
#     """Broadcasts a message to all the clients."""
#     for client in clients:
#         if client != from_client:
#             shared_secret = clients[client]['shared_secret']
#             client.send(msg)

def broadcast(msg, from_client=None):
    """Broadcasts a message to all the clients."""
    print("encrypted msg to send")
    print(msg)
    print("clients")
    print(clients)
    for sock in clients:
        print("sock")
        print(sock)
        if sock != from_client:  # Don't send back to the sender
            shared_secret_for_client = clients[sock]['shared_secret']

            # Encrypt the actual message with the shared secret of the current client
            encrypted_msg_for_client = encrypt_with_shared_secret(msg, shared_secret_for_client)

            # Send encrypted message to the current client
            sock.send(encrypted_msg_for_client)

clients = {}
addresses = {}

parser = argparse.ArgumentParser(description='This is the server for the chat.')
parser.add_argument('ip', type=str, nargs='?', default='127.0.0.1', help='the ip you want to bind. (default 127.0.0.1)')
parser.add_argument('-p', '--port', type=int, nargs='?', default=33000, help='the port. (default 33000)')
parser.add_argument('-s', '--buff-size', type=int, nargs='?', default=1024, help='the size of the buffer. (default 1024)')

args = parser.parse_args()
HOST = args.ip
PORT = args.port
BUFSIZ = args.buff_size
ADDR = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

if __name__ == "__main__":
    SERVER.listen(5)
    print(f'[INFO] Server started on {HOST}:{PORT}, buffer size: {BUFSIZ}')
    print("Waiting for connection...")
    try:
        ACCEPT_THREAD = Thread(target=accept_incoming_connections)
        ACCEPT_THREAD.start()
        ACCEPT_THREAD.join()
    except KeyboardInterrupt:
        print("\n[INFO] Server shutdown initiated...")
        SERVER.close()
        print("[INFO] Server closed.")
