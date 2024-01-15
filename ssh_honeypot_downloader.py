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

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    filename='ssh_honeypot_downloader.log')

# Disable InsecureRequestWarnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Retrieve Redis connection details from environment variables
REDIS_HOST = os.environ.get("REDIS_HOST")
REDIS_PORT = os.environ.get("REDIS_PORT")
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD")

# Connect to Redis
r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True)

def downloadURL(url):
    """
    Downloads a file from the given URL and saves it as a zip file.

    Args:
        url (str): The URL to download the file from.
    """
    # Make sure we haven't already checked this URL
    if not r.hexists("checked_urls", url):

        # Parse URL to extract file name
        a = urlparse(url)
        file_name = os.path.basename(a.path)

        # Initialize variables for file hashing and content
        logging.info('Downloading URL: {}'.format(url))
        m_sha256 = hashlib.sha256()
        file_digest = ''
        chunks = []

        try:
            # Fetch the content of the URL
            response = requests.get(url, verify=False, timeout=10)

            if response.status_code == 200:
                # Process content in chunks for hashing
                for data in response.iter_content(8192):
                    m_sha256.update(data)
                    chunks.append(data)

                # Calculate file digest
                file_digest = m_sha256.hexdigest()

                # Create directory for uploaded files if it doesn't exist
                directory = "uploaded_files"
                if not os.path.exists(directory):
                    os.makedirs(directory)

                # Create a zip file and write the content to it
                zip_filename = directory + "/" + file_digest + '.zip'
                if not os.path.isfile(zip_filename):
                    file_contents = b''.join(chunks)
                    with zipfile.ZipFile(zip_filename, mode='w') as myzip:
                        myzip.writestr(file_name, file_contents)
                    
            else:
                print("Did not receive http 200 for requested URL. Received: ", response.status_code)
                logging.info('Did not receive http 200 for requested URL. Received {}'.format(response.status_code))

        except Exception as err:
            print('*** Download URL failed: {}'.format(err))
            logging.info('*** Download URL failed: {}'.format(err))
            traceback.print_exc()

        # Add URL to Redis set so we don't check it again
        # (prevents honeypot from becoming a DoS weapon)
        r.hset("checked_urls", url, file_digest)

print("Waiting for URL to download...")
while True:
    try:
        # Pop a URL from the download queue in Redis
        url_to_download = r.lpop("download_queue")
        if url_to_download:
            downloadURL(url_to_download)

    except Exception as err:
        print('*** Download URL failed: {}'.format(err))
        logging.info('*** Download URL failed: {}'.format(err))
        traceback.print_exc()

    # Sleep for 1 second before checking for the next URL
    sleep(1)
