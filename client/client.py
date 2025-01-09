import socket
import scapy 
import struct
import threading

file_size = None
size_in_bytes = 0
tcp_connections = 0
udp_connections = 0






def main():

    startup_phase()
    #end of startup phase
    try: 
        address, server_udp_port, server_tcp_port = listen_phase()
    except KeyboardInterrupt:
        print("Received signal to close program, closed all sockets. Bye!")
        return
    #end of listening phase
    speed_test_phase(address, server_udp_port, server_tcp_port)
    


#----------------------------------start of startup phase---------------------------------
# gets the configuration of the tranfer by the user.
def startup_phase():
    file_size = input("Enter the file size: ").strip().upper()
    
    if file_size.endswith("GB"):
        size_in_bytes = int(file_size[:-2]) * 1024 ** 3
    elif file_size.endswith("MB"):
        size_in_bytes = int(file_size[:-2]) * 1024 ** 2
    else:
        print("Invalid file size format. Please specify in GB or MB.")
        return
    
    try:
        tcp_connections = int(input("Enter the number of TCP connections: ").strip())
        if tcp_connections < 0:
            print("TCP connections cannot be negative.")
            return
    except ValueError:
        print("Invalid input. Please enter an integer for TCP connections.")
        return
    
    try:
        udp_connections = int(input("Enter the number of UDP connections: ").strip())
        if udp_connections < 0:
            print("UDP connections cannot be negative.")
            return
    except ValueError:
        print("Invalid input. Please enter an integer for UDP connections.")
        return
    display_summary()

#A function that prints the configurations that the client got from the user
def display_summary(): 
    print("\nStartup Summary:")
    print(f"File Size: {file_size} ({size_in_bytes} bytes)")
    print(f"TCP Connections: {tcp_connections}")
    print(f"UDP Connections: {udp_connections}")

    print("\nEnd of startup state!")
    return
#-----------------------------------end of startup phase---------------------------------

#-----------------------------------start of listen phase-----------------------------------
# gets an offer message and validates it
def listen_phase():
    print("Client started, listening for offer requests...")
    while True:
        message, address = listen_to_broadcasts()     
        validation_result = validate_offer_message(message)     
        if validation_result:
            server_udp_port, server_tcp_port = validation_result
            return address, server_udp_port, server_tcp_port


#listens to port 13117 and returns when got a message
def listen_to_broadcasts():

    # Create a UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)  #why not working?
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    udp_socket.bind(("", 13117))  # Agreed port is 13117

    try:
        while True:
            message, address = udp_socket.recvfrom(1024)  # Buffer size of 1024 bytes
            print(f"\nReceived offer from {address}")
            return message, address
    finally:
        udp_socket.close()


#this function validates the offer message format and extracts the ports if valid
#return false or (udp port, tcp port)
def validate_offer_message(message):
    if len(message) < 9:
        print("REJECTED.\nThe message is too short.\nGoing back to listening to offers...")
        return False

    # Unpack the message (magic cookie, message type, and ports)
    try:
        magic_cookie, message_type, server_udp_port, server_tcp_port = struct.unpack('>I B H H', message[:9])
    except struct.error:
        print("REJECTED.\nFailed to unpack the message.\nGoing back to listening to offers...")
        return False

    if magic_cookie != 0xabcddcba:
        print("REJECTED.\nThe first four bytes do not match 0xabcddcba.\nGoing back to listening to offers...")
        return False

    if message_type != 0x2:
        print("REJECTED.\nThe message type is not 0x2 (offer message).\nGoing back to listening to offers...")
        return False

    print("The message is valid.")
    return server_udp_port, server_tcp_port
#----------------------------------------end of listen phase---------------------------------------


#----------------------------------------start of speed test phase---------------------------------------
#launches threads for each connection and port specified
def speed_test_phase(address, udp_port, tcp_port):

    threads = []

    # Create and start TCP threads
    for i in range(tcp_connections):
        thread = threading.Thread(target=tcp_thread, args=(address, tcp_port))
        threads.append(thread)
        thread.start()
    
    # Create and start UDP threads
    for i in range(udp_connections):
        thread = threading.Thread(target=udp_thread, args=(address, udp_port))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    print("Speed test phase completed.")

#thread responsible for tcp connection
def tcp_thread(address, port):
    try:
        # Create a TCP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
            print(f"TCP thread: Connecting to {address}:{port}")
            
            # Connect to the server
            tcp_socket.connect((address, port))
            print(f"TCP thread: Connected to {address}:{port}")
            
            #TODO send a request packet





            # Receive file data
            total_bytes_received = 0
            start_time = time.time()
            
            while True:
                data = tcp_socket.recv(4096)  # Buffer size: 4096 bytes
                if not data:
                    break  # No more data; end of file
                total_bytes_received += len(data)
            
            end_time = time.time()

            # Calculate download speed
            elapsed_time = end_time - start_time
            speed_mbps = (total_bytes_received * 8) / (elapsed_time * 1_000_000)  # Convert to Mbps

            print(f"TCP thread: Received {total_bytes_received} bytes in {elapsed_time:.2f} seconds "
                  f"({speed_mbps:.2f} Mbps)")

    except socket.error as e:
        print(f"TCP thread: Error with TCP connection to {address}:{port} - {e}")



#thread responsible for udp connection
def udp_thread(address, port):
    return
#----------------------------------------end of speed test phase---------------------------------------

if __name__ == "__main__":
    main()
