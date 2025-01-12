import socket
#from scapy.all import *
#from scapy.all import IP
import struct
import threading
import time


################################### 
# broadcast message format
###################################
magic_cookie = 0xabcddcba    # Magic cookie
broadcast_message_type = 0x2 # Offer message type
udp_port = 12345             # Server UDP port
tcp_port = 54321             # Server TCP port

################################### 
# request message format
###################################
# magic_cookie = 0xabcddcba  # 4 bytes
request_message_type = 0x3   # 1 byte
# file_size                  # 8 bytes

################################### 
# payload message format
###################################
# magic_cookie = 0xabcddcba  # 4 bytes
payload_message_type = 0x4   # 1 byte
# total_segment_count        # 8 bytes
# current_segment_count      # 8 bytes
# actual payload             # ?? bytes
payload_magic_cookie_index = 0
payload_message_type_index = 4
payload_total_segment_count_index = 5
payload_current_segment_count_index = 13
payload_actual_payload_index = 21


UDP_packet_size = 508 # bytes. this number is based on "The maximum safe UDP payload" we found over stackoverflow.
UDP_payload_size = UDP_packet_size - payload_actual_payload_index #packet_size - header_size
HOST = '127.0.0.1'
BROADCAST_IP = '255.255.255.255' 
UDP_BROADCAST_PORT = 13117
terminate = False

def listening_tcp_main(socket : socket.socket): #function that waits for new TCP connections. creates new thread for each new socket created.
    try:
        socket.listen(10)
        while(not terminate):
            newSocket , (sender_ip,sender_port) = socket.accept()
            print(f"Info(TCP main thread): made new connection: {sender_ip}:{sender_port}.")
            tcp_single_connection(newSocket)
    except Exception as e:
        print(f"Unexpected error(TCP main thread): {e}. closing socket.")
    finally:
        socket.close()
        return


def tcp_single_connection(socket : socket.socket): 
    #reach this function with a thread dedicated to handle established TCP connection.
    #at this point, waiting for request message (closing socket if invalid message).
    try:
        receive_buffer = bytearray(128)
        data = socket.recv(1024)
        decoded_data = data.decode('utf-8').strip()
        bytes_to_send = int(decoded_data)
        sender_ip, sender_port = socket.getpeername() #if we get here, we received a valid int, and we start to send the whole file through the socket.
        print(f"Info(TCP): starting to send {bytes_to_send} bytes to {sender_ip}:{sender_port}.")
        send_buffer = bytearray(1024)
        while(bytes_to_send>0):
            if(bytes_to_send>=1024):
                bytes_sent = socket.send(send_buffer)
                bytes_to_send -= bytes_sent
            else:
                bytes_sent = socket.send(send_buffer[:bytes_to_send])
                bytes_to_send -= bytes_sent
        print(f"Info(TCP): completed sending to {sender_ip}:{sender_port}. Closing socket.")
    except ValueError as e:
        print(f"Error(TCP): expected int value as file_size, received:{decoded_data}. sender: {sender_ip}:{sender_port}. Closing socket.")
    except Exception as e:
        print(f"Unexpected error(TCP): {e}. closing socket.")
    finally:
        socket.close()
        return

def listening_udp_main(socket: socket.socket):
    #function that waits for udp request messages. ignores invalid messages
    #if receives a valid request, creates a new thread that handles sending data to the request's sender.
    try:
        receive_buffer = bytearray(128)
        while(not terminate):
            num_received , sender = socket.recv_into(receive_buffer,128)
            sender_ip, sender_port = sender
            if(num_received == 13):
                magic_cookie1, message_type1, file_size = struct.unpack("!IBL",receive_buffer)
                if(magic_cookie1 == magic_cookie and message_type1 == 0x3):
                    udp_single_connection_thread = threading.Thread(target=udp_single_connection,args=(socket,sender_ip,sender_port,))
                    udp_single_connection_thread.start()
                else:
                    if(magic_cookie1 != magic_cookie):
                        print(f"Error(UDP): received message with invalid magic_cookie:{magic_cookie1} from {sender_ip}:{sender_port}, ignoring.")
                    else:
                        print(f"Error(UDP): received message with invalid message_type:{message_type1} from {sender_ip}:{sender_port}, ignoring.")
            else:
                print(f"Error(UDP): received message with invalid length:{num_received} from {sender_ip}:{sender_port}, ignoring.")
    except Exception as e:
        print(f"unexpected erorr(UDP main thread):{e}. closing socket.")
    finally:
        socket.close()
        return

def udp_single_connection(socket:socket.socket,dest_ip , dest_port ,bytes_to_send): #reach this function with a thread dedicated to send a file, after receiving UDP request.
    print(f"Info(UDP): starting to send {bytes_to_send} bytes to {dest_ip}:{dest_port}.")
    send_buffer = bytearray(UDP_packet_size) 
    send_buffer[payload_magic_cookie_index:payload_message_type_index] = struct.pack('>I',magic_cookie) 
    send_buffer[payload_message_type_index] = struct.pack('>B', payload_message_type)
    total_segments = bytes_to_send//UDP_payload_size #we'll send constant amount of payload in each message, defined by UDP_payload_size.
    if(total_segments * UDP_payload_size != bytes_to_send): #if bytes_to_send not divideable by payload size, the last packet will be of the remaining bytes that didn't fit.
        total_segments += 1
    send_buffer[payload_total_segment_count_index:payload_current_segment_count_index] = struct.pack('>Q', total_segments)
    curr_segment = 0
    try:

        while(bytes_to_send>0): #each iteration sends a single packet of UDP_packet_size (except the last packet, that may be smaller size).
            send_buffer[payload_current_segment_count_index:payload_actual_payload_index] = struct.pack('>Q', curr_segment)
            if(bytes_to_send>UDP_payload_size): 
                socket.sendto(send_buffer,(dest_ip, dest_port))
                bytes_to_send -= UDP_payload_size
            else: #last message to send. send header_size+bytes_to_send bytes.
                socket.sendto(send_buffer[:(UDP_packet_size-UDP_payload_size+bytes_to_send)],(dest_ip, dest_port)) 
                bytes_to_send = 0
            curr_segment += 1
        print(f"Info(UDP): completed sending to {dest_ip}:{dest_port}.")
    except Exception as e:
        print(f"Unexpected error(UDP): {e}.")
    return

def broadcast_main(socket : socket.socket): #sends broadcast message every second, as defined in the pdf.
    try:
        broadcast_message = struct.pack("!IBHH", magic_cookie,broadcast_message_type,udp_port,tcp_port)
        while(not terminate):
            socket.sendto(broadcast_message, (BROADCAST_IP,UDP_BROADCAST_PORT))
            time.sleep(1)
    except Exception as e:
        print(f"Unexpected Error(broadcast main):{e}.")
    finally:
        return
    
def main():
    tcp_receive_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #socket to receive new tcp connections.
    udp_receive_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #socket to receive udp packets (with formats as defined in the pdf).
    udp_broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #socket to broadcast offer message (with format as defined in the pdf).
    try: 
        tcp_receive_socket.bind((HOST, tcp_port))
        udp_receive_socket.bind((HOST, udp_port))
        udp_broadcast_socket.bind((HOST,UDP_BROADCAST_PORT))
        udp_broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        udp_broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        #3 "main" threads:
        tcp_listening_thread = threading.Thread(target=listening_tcp_main,args=(tcp_receive_socket,)) #waits for new tcp connections 
        tcp_listening_thread.start()
        udp_listening_thread = threading.Thread(target=listening_udp_main,args=(udp_receive_socket,)) #waits for udp request packets
        udp_listening_thread.start()
        broadcast_main(udp_broadcast_socket) #broadcasts every second.
    except Exception as e:
        print(f"error:{e}")


if __name__ =="__main__":
    main()