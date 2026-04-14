import socket
import ssl
import time  # NEW: Imported for performance metrics

HOST = '127.0.0.1'  
PORT = 8443

def start_client():
    
    context = ssl.create_default_context()
    
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    secure_client = context.wrap_socket(client_socket, server_hostname=HOST)
    
    try:
        secure_client.connect((HOST, PORT))
        print("[+] Securely connected to Fingerprint Server.")
        print("Enter targets to fingerprint in 'IP:PORT' format (e.g., 93.184.216.34:80). Type 'exit' to quit.")
        
        while True:
            target = input("\nTarget (IP:PORT)> ")
            if not target:
                continue
            
            # Check for exit command first
            if target.lower() == 'exit':
                secure_client.sendall(target.encode())
                break
                
            # Validation: Make sure the user typed a colon for the port
            if ':' not in target:
                print("[-] Invalid format. Please use exactly IP:PORT (e.g., 1.1.1.1:80)")
                continue
            
            # --- START PERFORMANCE TIMER ---
            start_time = time.time()
            
            # Send the request
            secure_client.sendall(target.encode())
            
            # Receive the answer
            response = secure_client.recv(4096).decode()
            
            # --- STOP PERFORMANCE TIMER ---
            end_time = time.time()
            round_trip_time = round(end_time - start_time, 4)
            
            # Print both the server's answer and the new metrics
            print(f"[Server Response] {response.strip()}")
            print(f"[Metrics] ⏱️ Round-Trip Latency: {round_trip_time} seconds")
            
    except Exception as e:
        print(f"[-] Connection error: {e}")
    finally:
        secure_client.close()

if __name__ == "__main__":
    start_client()
