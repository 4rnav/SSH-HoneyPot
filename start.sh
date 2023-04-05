#!/bin/bash
cat logo.txt
echo "CSE 4003 - CyberSecurity Project"
echo "Authors - Atharva Umbre, Atul Nair, Arnav Sarkar"
cd basic_ssh_honeypot_with_downloader
docker-compose build
docker-compose up

