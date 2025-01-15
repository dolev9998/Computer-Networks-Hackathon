import socket
import time
#import scapy 
import struct
import threading


#constants
UDP_BROADCAST_PORT = 13117
magic_cookie_constant = 0xabcddcba  # Magic cookie
offer_message_type = 0x2 
request_message_type = 0x3
payload_message_type = 0x4

#global vars
file_size = None
requested_size_in_bytes = 0
tcp_connections = 0
udp_connections = 0






def main():
    while not startup_phase():
        print("Try again!")
    #end of startup phase


    try:
        while True:
            address, server_udp_port, server_tcp_port = listen_phase()
            #end of listening phase
            speed_test_phase(address, server_udp_port, server_tcp_port)
            #end of speed-test phase
    except KeyboardInterrupt:
        print("Received signal to close program, closed all sockets. Bye!")



#----------------------------------start of startup phase---------------------------------
# gets the configuration of the tranfer by the user.
def startup_phase():
    global file_size
    global requested_size_in_bytes
    global tcp_connections
    global udp_connections


    file_size = input("Enter the file size: ").strip().upper()
    
    if file_size.endswith("GB"):
        requested_size_in_bytes = int(file_size[:-2]) * 1024 ** 3
    elif file_size.endswith("MB"):
        requested_size_in_bytes = int(file_size[:-2]) * 1024 ** 2
    else:
        print("Invalid file size format. Please specify in GB or MB.")
        return False
    if requested_size_in_bytes == 0:
        print("Invalid size given.")
        return False

    try:
        tcp_connections = int(input("Enter the number of TCP connections: ").strip())
        if tcp_connections < 0:
            print("TCP connections cannot be negative.")
            return False
    except ValueError:
        print("Invalid input. Please enter an integer for TCP connections.")
        return False
    
    try:
        udp_connections = int(input("Enter the number of UDP connections: ").strip())
        if udp_connections < 0:
            print("UDP connections cannot be negative.")
            return False
    except ValueError:
        print("Invalid input. Please enter an integer for UDP connections.")
        return False

    display_summary()
    return True

#A function that prints the configurations that the client got from the user
def display_summary(): 
    print("\nStartup Summary:")
    print(f"File Size: {file_size} ({requested_size_in_bytes} bytes)")
    print(f"TCP Connections: {tcp_connections}")
    print(f"UDP Connections: {udp_connections}")

    print("\nEnd of startup phase!")
    return
#-----------------------------------end of startup phase---------------------------------

#-----------------------------------start of listen phase-----------------------------------
# gets an offer message and validates it
def listen_phase():
    print("Client started, listening for offer requests...")
    while True:
        message, (address , port) = listen_to_broadcasts()     
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

    udp_socket.bind(("", UDP_BROADCAST_PORT))  # Agreed port is 13117

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

    if magic_cookie != magic_cookie_constant:
        print("REJECTED.\nThe first four bytes do not match 0xabcddcba.\nGoing back to listening to offers...")
        return False

    if message_type != offer_message_type:
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
        thread = threading.Thread(target=tcp_thread, args=(i+1,address, tcp_port))
        threads.append(thread)
        thread.start()
    
    i = 1
    # Create and start UDP threads
    for i in range(udp_connections):
        thread = threading.Thread(target=udp_thread, args=(i+1, address, udp_port))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    print("Speed test phase completed.")

#thread responsible for tcp connection
def tcp_thread(index ,server_address, server_port):
    try:
        # Create a TCP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
            print(f"TCP thread {index}: Connecting to {server_address}:{server_port}")
            
            # Connect to the server
            tcp_socket.connect((server_address, server_port))
            print(f"TCP thread {index}: Connected to {server_address}:{server_port}")
            
            size_message = f"{requested_size_in_bytes}\n" 
            encoded_message = size_message.encode('utf-8')  
            tcp_socket.sendall(encoded_message) 



            # Receive file data
            total_bytes_received = 0
            start_time = time.time()
            

            while total_bytes_received < requested_size_in_bytes:
                data = tcp_socket.recv(1024) 
                if not data:
                    print(f"TCP Thread {index}: Server closed the connection.")
                    break
                total_bytes_received += len(data) #TODO: need to check received > asked?
            
            end_time = time.time()

            # Calculate download speed
            elapsed_time = end_time - start_time
            speed_mbps = (total_bytes_received * 8) / (elapsed_time * 1000000)  # Convert to Mbps
            print(f"TCP transfer #{index} finished, total time: {elapsed_time:.2f} seconds, total speed: {speed_mbps:.2f} Mbps")

    except socket.error as e:
        print(f"TCP thread {index}: Error with TCP connection to {server_address}:{server_port} - {e}")
    except Exception as e:
        print(f"TCP thread {index}: Error with TCP packet from {server_address}:{server_port} - {e}")



#thread responsible for udp connection
def udp_thread(index, server_address, server_port):
    try:
        # Create a UDP socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
            udp_socket.settimeout(1.0)
            print(f"UDP thread {index}: Listening for data from {server_address}:{server_port}")

            request_packet = create_request_packet()
            udp_socket.sendto(request_packet, (server_address, server_port))



            total_bytes_received = 0
            total_packets_received = 0
            total_packets_expected = (requested_size_in_bytes + 507) // 508 #remainder results in another packet
            start_time = time.time()

            while total_bytes_received < requested_size_in_bytes:
                try:
                    data, sender_address = udp_socket.recvfrom(508)
                    # Verify the source
                    if sender_address != (server_address, server_port):
                        print(f"UDP Thread {index}: Ignored packet from {sender_address}. Expected: {(server_address, server_port)}")
                        continue

                    payload_length = check_payload_packet(data)

                    if payload_length:
                        total_packets_received += 1
                        total_bytes_received += len(data)
                    else:
                        print(f"UDP Thread {index}: Received a malformed packet.")

                except socket.timeout:
                    # Conclude transfer after timeout
                    print(f"UDP Thread {index}: No data received for 1 second, concluding transfer.")
                    break

            end_time = time.time()
            if not total_bytes_received < requested_size_in_bytes:
                end_time -= 1

            # Calculate statistics
            elapsed_time = end_time - start_time
            speed_mbps = (total_bytes_received * 8) / (elapsed_time * 1000000) 
            success_percentage = (total_packets_received / total_packets_expected) * 100


            # Print results
            print(f"UDP transfer #{index} finished, total time: {elapsed_time:.2f} seconds, "
                  f"total speed: {speed_mbps:.2f} Mbps, "
                  f"successfully received: {success_percentage:.2f}% packets.")

    except socket.error as e:
        print(f"UDP thread {index}: Error with UDP connection to {server_address}:{server_port} - {e}")



# creates a request packet
def create_request_packet():



    # Pack the data into a binary format
    request_packet = struct.pack('!IBQ', magic_cookie_constant, request_message_type, requested_size_in_bytes) 
    # make sure it stays in bytes....

    return request_packet

# makes sure the payload packet is in correct form and returns the payload length
def check_payload_packet(packet):

    # Check if the packet is at least 21 bytes long (4 + 1 + 8 + 8)
    if len(packet) < 21:
        print("Invalid packet: Too short.")
        return False
    
    try:
        # Unpack the header: Magiccookie (4 bytes), Messagetype (1 byte),
        magic_cookie, message_type, total_segment_count, current_segment_count = struct.unpack('!IBQQ', packet[:21])
        
        if magic_cookie != magic_cookie_constant:
            print("Invalid packet: Magic cookie mismatch.")
            return False
        
        if message_type != payload_message_type:
            print("Invalid packet: Incorrect message type.")
            return False

        payload_length = len(packet) - 21
        return payload_length

    except struct.error:
        print("Invalid packet: Failed to unpack.")
        return False



#----------------------------------------end of speed test phase---------------------------------------

if __name__ == "__main__":
    main()
