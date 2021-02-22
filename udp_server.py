import socket
import time
import argparse

class UDP_Server:
    def __init__(self, bind_host, bind_port):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def IO(self):
        self.server_socket.bind((self.bind_host, self.bind_port))
        print("UDP Server listening ar {}:{}".format(self.bind_host, self.bind_port))

        try:
            while True:
                data, addr = self.server_socket.recvfrom(1024)
                print("Message from: {}".format(addr, data))
                if data == b"What is the time?":
                    self.server_socket.sendto(str(time.time()).encode(), addr)
        except KeyboardInterrupt:
            print("Exiting")


def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-host", action="store", type=str)
    parser.add_argument("-port", action="store", type=int)
    args = parser.parse_args()
    return args

def main():
    args = arguments()
    server = UDP_Server(args.host, args.port)
    server.IO()

if __name__ == "__main__":
    main()
        
   