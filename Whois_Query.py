import socket
import validators


def whois_lookup(domain:str):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("whois.verisign-grs.com", 43)) # whois protocol, connect to the whois server, then grab domain info from there
    s.send(f"{domain}\r\n".encode())
    response = s.recv(4096).decode()
    s.close()
    return response


while True:
    domain_name = input("Enter a domain name to lookup: ").strip()
    if validators.domain(domain_name):
        break
    else:
        print("Invalid domain name. Please enter a valid domain.")
    
    
print(whois_lookup(domain_name))
    
