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
#from paramiko import b, u, decodebytes

REDIS_HOST=os.environ.get("REDIS_HOST")
REDIS_PORT=os.environ.get("REDIS_PORT")
REDIS_PASSWORD=os.environ.get("REDIS_PASSWORD")
r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True)

HOST_KEY = paramiko.RSAKey(filename='server.key')
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"

UP_KEY = '\x1b[A'.encode()
DOWN_KEY = '\x1b[B'.encode()
RIGHT_KEY = '\x1b[C'.encode()
LEFT_KEY = '\x1b[D'.encode()
BACK_KEY = '\x7f'.encode()

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    filename='ssh_honeypot.log')

def detect_url(command, client_ip):
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    result = re.findall(regex, command)
    if result:
        for ar in result:
            for url in ar:
                if url != '':
                    logging.info('New URL detected ({}): {}'.format(client_ip, url))
                    r.lpush("download_queue", url)

    ip_regex = r"([0-9]+(?:\.[0-9]+){3}\/\S*)"
    ip_result = re.findall(ip_regex, command)
    if ip_result:
        for ip_url in ip_result:
            if ip_url != '':
                logging.info('New IP-based URL detected ({}): {}'.format(client_ip, ip_url))
                r.lpush("download_queue", ip_url)

def handle_cmd(cmd, chan, ip):

    detect_url(cmd, ip)
    response = ""

    if cmd.startswith("ls"):
        response = "users.txt"
    elif cmd.startswith("pwd"):
        response = "/home/root"
    elif cmd.startswith("cat /proc/cpuinfo | grep name | wc -l"):
        response = "2"
    elif cmd.startswith("uname -a"):
        response = "Linux server 4.15.0-147-generic #151-Ubuntu SMP Fri Jun 18 19:21:19 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux"
    elif cmd.startswith("cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'"):
        response = "Intel(R) Xeon(R) CPU E5-2680 v3 @"
    elif cmd.startswith("free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'"):
        response = "7976 5167 199 1 2609 2519"
    elif cmd.startswith("ls -lh $(which ls)"):
        response = "-rwxr-xr-x 1 root root 131K Jan 18  2018 /bin/ls"
    elif cmd.startswith("crontab -l "):
        response = "no crontab for root"

    if response != '':
        logging.info('Response from honeypot ({}): '.format(ip, response))
        response = response + "\r\n"
    chan.send(response)


class BasicSshHoneypot(paramiko.ServerInterface):

    client_ip = None

    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        logging.info('client called check_channel_request ({}): {}'.format(
                    self.client_ip, kind))
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        logging.info('client called get_allowed_auths ({}) with username {}'.format(
                    self.client_ip, username))
        return "publickey,password"

    def check_auth_publickey(self, username, key):
        fingerprint = u(hexlify(key.get_fingerprint()))
        logging.info('client public key ({}): username: {}, key name: {}, md5 fingerprint: {}, base64: {}, bits: {}'.format(
                    self.client_ip, username, key.get_name(), fingerprint, key.get_base64(), key.get_bits()))
        return paramiko.AUTH_PARTIALLY_SUCCESSFUL        

    def check_auth_password(self, username, password):
        # Accept all passwords as valid by default
        logging.info('new client credentials ({}): username: {}, password: {}'.format(
                    self.client_ip, username, password))
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        command_text = str(command.decode("utf-8"))
        handle_cmd(command_text, channel, self.client_ip)
        logging.info('client sent command via check_channel_exec_request ({}): {}'.format(
                    self.client_ip, command))
        return True
