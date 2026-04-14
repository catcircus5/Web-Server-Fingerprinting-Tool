import socket
import ssl
import threading


HOST = '0.0.0.0'  
PORT = 8443
CERT_FILE = 'server.crt'
KEY_FILE = 'server.key'

def grab_banner(target_ip, port):
    """Connects to the target, handles specific protocols, and extracts the banner."""
    try:
        # Create a raw, unencrypted socket for the outbound target connection
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # OPTIMIZATION: Set a 5-second timeout so dead IPs don't freeze the server
        target_socket.settimeout(5.0) 
        
        # Connect to the target
        target_socket.connect((target_ip, port))

        # --- PROTOCOL: FTP (Port 21) ---
        if port == 21:
            # FTP sends the banner immediately upon connection
            banner = target_socket.recv(1024).decode('utf-8', errors='ignore').strip()
            target_socket.close()
            # Grab the first line of the FTP welcome message
            first_line = banner.split('\n')[0] if banner else "No FTP banner returned."
            return f"FTP Service -> {first_line}"

        # --- PROTOCOL: HTTP/HTTPS (Port 80/443) ---
        elif port in [80, 443]:
            # HTTP requires us to ask for the page first
            request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
            target_socket.sendall(request.encode())
            
            response = target_socket.recv(4096).decode('utf-8', errors='ignore')
            target_socket.close()
            
            # Scan for the "Server:" header
            for line in response.split('\n'):
                if line.lower().startswith('server:'):
                    return line.strip()
            return "HTTP Server header not found in response."

        # --- PROTOCOL: Generic (Any other port) ---
        else:
            banner = target_socket.recv(1024).decode('utf-8', errors='ignore').strip()
            target_socket.close()
            return f"Generic Banner -> {banner[:50]}..." # Return first 50 chars

    except socket.timeout:
        return f"[Error] Connection to {target_ip}:{port} timed out."
    except Exception as e:
        return f"[Error] Could not grab banner: {str(e)}"

def handle_client(conn, addr):
    """Handles an individual client connection concurrently."""
    print(f"[+] Secure connection established with {addr}")
    try:
        while True:
            data = conn.recv(1024).decode()
            if not data or data.lower() == 'exit':
                break
            
            print(f"[*] Received target from {addr}: {data}")
            
            
            try:
                target_ip, target_port = data.split(':')
                target_port = int(target_port)
                
                
                result = grab_banner(target_ip, target_port)
                
                
                conn.sendall(f"Result for {data} -> {result}\n".encode())
            except ValueError:
                conn.sendall(b"Invalid format. Please send as IP:PORT\n")
                
    except Exception as e:
        print(f"[-] Error with {addr}: {e}")
    finally:
        print(f"[-] Connection closed for {addr}")
        conn.close()

def start_server():
    """Initializes the secure server."""
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    secure_server = context.wrap_socket(server_socket, server_side=True)
    
    print(f"[*] Secure Fingerprint Server listening on {HOST}:{PORT}")
    
    try:
        while True:
            
            client_conn, client_addr = secure_server.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_conn, client_addr))
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server.")
    finally:
        secure_server.close()

if __name__ == "__main__":
    start_server()
