import argparse
import socket
from time import sleep

class UDP_Client:
    def __init__(self, target_host, target_port):
        self.target_host = target_host
        self.target_port = target_port

    def IO(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            while True:
                sleep(2)
                client_socket.sendto(b"What is the time?", (self.target_host, self.target_port))
                data, addr = client_socket.recvfrom(1024)
                print("The time is:", data.decode())
                print("Message from:", addr, "\n")
        except KeyboardInterrupt:
            print("Exiting")


def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-host", default="localhost", action="store")
    parser.add_argument("-port", action="store", type=int)
    args = parser.parse_args()
    return args

def main():
    args = arguments()
    client = UDP_Client(args.host, args.port)
    client.IO()

if __name__ == '__main__':
    main()
