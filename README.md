# Honeypot-SSH

A honeypot is a security mechanism used to detect, deflect or study attempts by unauthorized users to access information systems. An SSH honeypot is a system designed to attract and trap potential attackers who are trying to gain unauthorized access to a network or server using the SSH (Secure Shell) protocol.

## Deployment

Setup server key

```bash
  ssh-keygen -t rsa -f server.key
```

Deploy docker containers

```bash
  docker-compose build && docker-compose up
```

## Roadmap

- Separate microservices for connection handling and file downloader.

- Use the file digest to generate a report about the malicious file using some API based file scanner (Virustotal)

## Tech Stack

**Deployment** Docker Compose

**Server:** Python (Paramiko)

## License

[MIT](https://choosealicense.com/licenses/mit/)
