#!/usr/bin/env python
import sys
import os
import traceback
import paramiko
import logging
import redis
import requests
import urllib3
import hashlib
import zipfile
from time import sleep
from urllib.parse import urlparse

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    filename='ssh_honeypot_downloader.log')
