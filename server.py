#!/usr/bin/env python3
"""Server for multithreaded (asynchronous) chat application."""
import argparse
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from nacl.public import PrivateKey, Box

def accept_incoming_connections():
    """Sets up handling for incoming clients."""
    while True:
        client, client_address = SERVER.accept()
        print("%s:%s has connected." % client_address)
        client.send(bytes("Greetings from the cave! Now type your name and press enter!", "utf8"))
        addresses[client] = client_address
        Thread(target=handle_client, args=(client,)).start()

def handle_client(client):
    """Handles a single client connection."""
    name = client.recv(BUFSIZ).decode("utf8")
    welcome = 'Welcome %s! If you ever want to quit, type {quit} to exit.' % name
    client.send(bytes(welcome, "utf8"))
    msg = "%s has joined the chat!" % name
    broadcast(bytes(msg, "utf8"))
    clients[client] = name

    while True:
        msg = client.recv(BUFSIZ)
        if msg != bytes("{quit}", "utf8"):
            broadcast(msg, name+": ")
        else:
            client.send(bytes("{quit}", "utf8"))
            client.close()
            del clients[client]
            broadcast(bytes("%s has left the chat." % name, "utf8"))
            break

def broadcast(msg, prefix=""):
    """Broadcasts a message to all the clients."""
    for sock in clients:
        # Encrypt the message for each recipient using their public key
        recipient_public_key = recipients[sock]
        encrypted_msg = recipient_public_key.encode() + box.encrypt(prefix.encode() + msg)
        sock.send(encrypted_msg)

clients = {}
addresses = {}
recipients = {}  # Store public keys of clients

# Generate server's public and private keys
server_private_key = PrivateKey.generate()
server_public_key = server_private_key.public_key
box = Box(server_private_key, server_public_key)

#----Now comes the arguments part----
parser = argparse.ArgumentParser(description='This is the server for the chat.')
parser.add_argument('ip', type=str, nargs='?', default='127.0.0.1',
                    help='the ip you want to bind. (default 127.0.0.1)')

parser.add_argument('-p','--port', type=int, nargs='?', default=33000,
                    help='the port. (default 33000)')  
parser.add_argument('-s','--buff-size', type=int, nargs='?', default=1024,
                    help='the size of the buffer. (default 1024)')
                    
args = parser.parse_args()
HOST=args.ip
PORT=args.port 
BUFSIZ = args.buff_size

ADDR = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

if __name__ == "__main__":
    SERVER.listen(5)
    print(f'[INFO] Server started on {HOST}:{PORT}, buffer size: {BUFSIZ}')
    print("Waiting for connection...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    SERVER.close()








































# #!/usr/bin/env python3
# """Server for multithreaded (asynchronous) chat application."""
# import argparse
# from socket import AF_INET, socket, SOCK_STREAM
# from threading import Thread
# from nacl.public import PrivateKey, Box


# def accept_incoming_connections():
#     """Sets up handling for incoming clients."""
#     while True:
#         client, client_address = SERVER.accept()
#         print("%s:%s has connected." % client_address)
#         client.send(bytes("Greetings from the cave! Now type your name and press enter!", "utf8"))
#         addresses[client] = client_address
#         Thread(target=handle_client, args=(client,)).start()


# def handle_client(client):  # Takes client socket as argument.
#     """Handles a single client connection."""

#     name = client.recv(BUFSIZ).decode("utf8")
#     welcome = 'Welcome %s! If you ever want to quit, type {quit} to exit.' % name
#     client.send(bytes(welcome, "utf8"))
#     msg = "%s has joined the chat!" % name
#     broadcast(bytes(msg, "utf8"))
#     clients[client] = name

#     while True:
#         msg = client.recv(BUFSIZ)
#         if msg != bytes("{quit}", "utf8"):
#             broadcast(msg, name+": ")
#         else:
#             client.send(bytes("{quit}", "utf8"))
#             client.close()
#             del clients[client]
#             broadcast(bytes("%s has left the chat." % name, "utf8"))
#             break


# def broadcast(msg, prefix=""):  # prefix is for name identification.
#     """Broadcasts a message to all the clients."""

#     for sock in clients:
#         sock.send(bytes(prefix, "utf8")+msg)

        
# clients = {}
# addresses = {}


# #----Now comes the arguments part----
# parser = argparse.ArgumentParser(description='This is the server for the chat.')
# parser.add_argument('ip', type=str, nargs='?', default='127.0.0.1',
#                     help='the ip you want to bind. (default 127.0.0.1)')

# parser.add_argument('-p','--port', type=int, nargs='?', default=33000,
#                     help='the port. (default 33000)')  
# parser.add_argument('-s','--buff-size', type=int, nargs='?', default=1024,
#                     help='the size of the buffer. (default 1024)')
                    
# args = parser.parse_args()
# HOST=args.ip
# PORT=args.port 
# BUFSIZ = args.buff_size

# ADDR = (HOST, PORT)

# SERVER = socket(AF_INET, SOCK_STREAM)
# SERVER.bind(ADDR)

# if __name__ == "__main__":
#     SERVER.listen(5)
#     print(f'[INFO] Server started on {HOST}:{PORT}, buffer size: {BUFSIZ}')
#     print("Waiting for connection...")
#     ACCEPT_THREAD = Thread(target=accept_incoming_connections)
#     ACCEPT_THREAD.start()
#     ACCEPT_THREAD.join()
#     SERVER.close()
