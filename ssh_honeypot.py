#!/usr/bin/env python
import argparse
import threading
import socket
import sys
import os
import traceback
import re
import logging
import paramiko
import redis
from datetime import datetime
from binascii import hexlify

# Retrieve Redis connection details from environment variables
REDIS_HOST = os.environ.get("REDIS_HOST")
REDIS_PORT = os.environ.get("REDIS_PORT")
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD")

# Connect to Redis
r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True)

# Load RSA host key for SSH server
HOST_KEY = paramiko.RSAKey(filename='server.key')

# SSH Banner to appear more convincing
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"

# Arrow keys and backspace characters
UP_KEY = '\x1b[A'.encode()
DOWN_KEY = '\x1b[B'.encode()
RIGHT_KEY = '\x1b[C'.encode()
LEFT_KEY = '\x1b[D'.encode()
BACK_KEY = '\x7f'.encode()

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    filename='ssh_honeypot.log')

def detect_url(command, client_ip):
    """
    Detects URLs and IP-based URLs in the command and pushes them to the download queue in Redis.

    Args:
        command (str): The command received from the client.
        client_ip (str): The IP address of the client.
    """
    # Regular expression to detect URLs
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    result = re.findall(regex, command)
    if result:
        for ar in result:
            for url in ar:
                if url != '':
                    logging.info('New URL detected ({}): {}'.format(client_ip, url))
                    r.lpush("download_queue", url)

    # Regular expression to detect IP-based URLs
    ip_regex = r"([0-9]+(?:\.[0-9]+){3}\/\S*)"
    ip_result = re.findall(ip_regex, command)
    if ip_result:
        for ip_url in ip_result:
            if ip_url != '':
                logging.info('New IP-based URL detected ({}): {}'.format(client_ip, ip_url))
                r.lpush("download_queue", ip_url)

def handle_cmd(cmd, chan, ip):
    """
    Handles the commands received from the client and sends appropriate responses.

    Args:
        cmd (str): The command received from the client.
        chan (Channel): The SSH channel.
        ip (str): The IP address of the client.
    """
    detect_url(cmd, ip)
    response = ""

    # Handling specific commands and providing fake responses
    if cmd.startswith("ls"):
        response = "users.txt"
    elif cmd.startswith("pwd"):
        response = "/home/root"
    # ... (other commands)

    if response != '':
        logging.info('Response from honeypot ({}): '.format(ip, response))
        response = response + "\r\n"
    chan.send(response)

class BasicSshHoneypot(paramiko.ServerInterface):
    """
    Implementation of the Paramiko ServerInterface for the SSH honeypot.
    """
    client_ip = None

    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    # ... (other methods)

def handle_connection(client, addr):
    """
    Handles a new SSH connection from a client.

    Args:
        client (Socket): The client socket.
        addr (tuple): The address of the client.
    """
    client_ip = addr[0]
    logging.info('New connection from: {}'.format(client_ip))
    print('New connection from: {}'.format(client_ip))

    try:
        # Initialize Paramiko transport
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)
        transport.local_version = SSH_BANNER
        server = BasicSshHoneypot(client_ip)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            print('*** SSH negotiation failed.')
            raise Exception("SSH negotiation failed")

        # Wait for authentication
        chan = transport.accept(10)
        if chan is None:
            print('*** No channel (from '+client_ip+').')
            raise Exception("No channel")
        
        chan.settimeout(10)

        # Log client details
        log_client_details(client_ip, transport)

        # Wait for shell request
        server.event.wait(10)
        if not server.event.is_set():
            logging.info('** Client ({}): never asked for a shell'.format(client_ip))
            raise Exception("No shell request")

        try:
            # Send welcome message
            chan.send("Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-128-generic x86_64)\r\n\r\n")
            run = True
            while run:
                # Send command prompt
                chan.send("$ ")
                command = ""
                while not command.endswith("\r"):
                    transport = chan.recv(1024)
                    print(client_ip+"- received:",transport)
                    # Echo input to simulate a basic terminal
                    if(
                        transport != UP_KEY
                        and transport != DOWN_KEY
                        and transport != LEFT_KEY
                        and transport != RIGHT_KEY
                        and transport != BACK_KEY
                    ):
                        chan.send(transport)
                        command += transport.decode("utf-8")
                
                chan.send("\r\n")
                command = command.rstrip()
                logging.info('Command received ({}): {}'.format(client_ip, command))

                if command == "exit":
                    logging.info('Connection closed (via exit command): {}'.format(client_ip))
                    run = False
                else:
                    handle_cmd(command, chan, client_ip)

        except Exception as err:
            print('!!! Exception: {}: {}'.format(err.__class__, err))
            try:
                transport.close()
            except Exception:
                pass

        chan.close()

    except Exception as err:
        print('!!! Exception: {}: {}'.format(err.__class__, err))
        try:
            transport.close()
        except Exception:
            pass

def log_client_details(client_ip, transport):
    """
    Log details about the connected client.

    Args:
        client_ip (str): The IP address of the client.
    """
    if transport.remote_mac != '':
        logging.info('Client mac ({}): {}'.format(client_ip, transport.remote_mac))
    if transport.remote_compression != '':
        logging.info('Client compression ({}): {}'.format(client_ip, transport.remote_compression))
    if transport.remote_version != '':
        logging.info('Client SSH version ({}): {}'.format(client_ip, transport.remote_version))
    if transport.remote_cipher != '':
        logging.info('Client SSH cipher ({}): {}'.format(client_ip, transport.remote_cipher))

def start_server(port, bind):
    """Init and run the SSH server."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind, port))
    except Exception as err:
        print('*** Bind failed: {}'.format(err))
        traceback.print_exc()
        sys.exit(1)

    threads = []
    while True:
        try:
            sock.listen(100)
            print('Listening for connection on port {} ...'.format(port))
            client, addr = sock.accept()
        except Exception as err:
            print('*** Listen/accept failed: {}'.format(err))
            traceback.print_exc()
        new_thread = threading.Thread(target=handle_connection, args=(client, addr))
        new_thread.start()
        threads.append(new_thread)

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Run an SSH honeypot server')
    parser.add_argument("--port", "-p", help="The port to bind the SSH server to (default 22)", default=2222, type=int, action="store")
    parser.add_argument("--bind", "-b", help="The address to bind the SSH server to", default="", type=str, action="store")
    args = parser.parse_args()
    
    # Start the SSH server
    start_server(args.port, args.bind)
