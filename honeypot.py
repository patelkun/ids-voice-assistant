import socket
import threading
import datetime
import json

honeypot_logs = []

def log_attack(ip, port, data):
    log = {
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "port": port,
        "data": data[:200] if data else "No data"
    }
    honeypot_logs.append(log)
    print(f"🍯 Honeypot hit! IP: {ip} Port: {port} Data: {data[:50]}")
    
    # Save to file
    with open("honeypot_logs.json", "w") as f:
        json.dump(honeypot_logs, f, indent=2)

def fake_ssh_server(port=2222):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    print(f"🍯 Fake SSH server listening on port {port}")
    
    while True:
        try:
            client, addr = server.accept()
            ip = addr[0]
            # Fake SSH banner bhejo
            client.send(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")
            data = client.recv(1024).decode("utf-8", errors="ignore")
            log_attack(ip, port, data)
            client.send(b"Permission denied (publickey,password)\r\n")
            client.close()
        except:
            pass

def fake_http_server(port=8080):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    print(f"🍯 Fake HTTP server listening on port {port}")
    
    while True:
        try:
            client, addr = server.accept()
            ip = addr[0]
            data = client.recv(1024).decode("utf-8", errors="ignore")
            log_attack(ip, port, data)
            # Fake response
            response = """HTTP/1.1 200 OK
Content-Type: text/html

<html><body><h1>Admin Panel</h1>
<form>Username: <input><br>Password: <input type=password><br>
<input type=submit value=Login></form></body></html>"""
            client.send(response.encode())
            client.close()
        except:
            pass

def fake_ftp_server(port=2121):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    print(f"🍯 Fake FTP server listening on port {port}")
    
    while True:
        try:
            client, addr = server.accept()
            ip = addr[0]
            client.send(b"220 FTP Server Ready\r\n")
            data = client.recv(1024).decode("utf-8", errors="ignore")
            log_attack(ip, port, data)
            client.send(b"530 Login incorrect\r\n")
            client.close()
        except:
            pass

def start_honeypot():
    print("🍯 Honeypot system shuru ho raha hai...")
    
    threads = [
        threading.Thread(target=fake_ssh_server, daemon=True),
        threading.Thread(target=fake_http_server, daemon=True),
        threading.Thread(target=fake_ftp_server, daemon=True),
    ]
    
    for t in threads:
        t.start()
    
    print("✅ Honeypot active!")
    print("   Fake SSH  → port 2222")
    print("   Fake HTTP → port 8080")
    print("   Fake FTP  → port 2121")
    
    return threads

if __name__ == "__main__":
    threads = start_honeypot()
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Honeypot band ho raha hai...")