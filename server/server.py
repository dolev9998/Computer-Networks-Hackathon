import socket
import scapy 
import struct
import threading

HOST = '127.0.0.1' #TODO: maybe receive as param?
TCP_PORT = 65432 #TODO: maybe receive as param?
BROADCAST_IP = '255.255.255.255' #TODO: maybe receive as param?
UDP_BROADCAST_PORT = 35555 #TODO: maybe receive as param?

def listening_main(socket):
    return

def broadcast_main(socket):
    return

if __name__ =="__main__":
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    udp_boradcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_socket.bind((HOST, PORT))
        listening_thread = threading.Thread(target=listening_main,args=(server_socket,))

    except Exception as e:
        print(f"error:{e}")
    #finally:
        #server_socket.close()