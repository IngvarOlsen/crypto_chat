#!/usr/bin/env python3
"""Script for Tkinter GUI chat client."""
import argparse
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import tkinter
import nacl.utils
import nacl.secret
# import nacl.secret
from nacl.public import PrivateKey, Box

title_chat = 'Chatter'

skclient = PrivateKey.generate()
pkclient = skclient.public_key
client_public_key = pkclient.encode(encoder=nacl.encoding.HexEncoder)


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


def receive():
    """Handles receiving of messages."""
    global title_chat
    while True:
        try:
            encrypted_shared_secret = client_socket.recv(256)
            encrypted_msg = client_socket.recv(BUFSIZ)
            print('encrypted_msg')
            print(encrypted_msg)
            print('shared_secret')
            print(shared_secret)
        
            decrypted_msg = decrypt_with_shared_secret(encrypted_msg, shared_secret).decode("utf8")  
            print('decrypted_msg')
            print(decrypted_msg)

            msg_list.insert(tkinter.END, decrypted_msg)
            if decrypted_msg.startswith('Welcome') and title_chat == 'Chatter':
                title_chat += ' ' + decrypted_msg.split()[1]
                top.title(title_chat)
        except OSError:
            break


def send(event=None):
    """Handles sending of messages."""
    msg = my_msg.get()
    my_msg.set("")

    encrypted_msg = encrypt_with_shared_secret(bytes(msg, "utf8"), shared_secret)

    client_socket.send(encrypted_msg)

    if msg == "{quit}":
        client_socket.close()
        top.quit()


def on_closing(event=None):
    """This function is to be called when the window is closed."""
    my_msg.set("{quit}")
    send()

# GUI setup
top = tkinter.Tk()
top.title(title_chat)

messages_frame = tkinter.Frame(top)
my_msg = tkinter.StringVar()
my_msg.set("Username?")
scrollbar = tkinter.Scrollbar(messages_frame)
msg_list = tkinter.Listbox(messages_frame, height=15, width=50, yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()
messages_frame.pack()

entry_field = tkinter.Entry(top, textvariable=my_msg)
entry_field.bind("<Return>", send)
entry_field.pack()
send_button = tkinter.Button(top, text="Send", command=send)
send_button.pack()

top.protocol("WM_DELETE_WINDOW", on_closing)

# Argument parsing
parser = argparse.ArgumentParser(description='This is the client for the chat.')
parser.add_argument('ip', type=str, nargs='?', default='127.0.0.1',
                    help='the ip you want to connect to. (default 127.0.0.1)')
parser.add_argument('-p', '--port', type=int, nargs='?', default=33000, help='the port. (default 33000)')
parser.add_argument('-s', '--buff-size', type=int, nargs='?', default=1024, help='the size of the buffer. (default 1024)')

args = parser.parse_args()
HOST = args.ip
PORT = args.port
BUFSIZ = args.buff_size
ADDR = (HOST, PORT)

# Socket setup
client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)

server_public_key_hex = client_socket.recv(64).decode('utf-8')
server_public_key = nacl.public.PublicKey(server_public_key_hex, encoder=nacl.encoding.HexEncoder)
shared_secret = generate_shared_key(skclient, server_public_key)

client_socket.send(client_public_key)

receive_thread = Thread(target=receive)
receive_thread.start()
tkinter.mainloop()
