import socket
import argparse

class UDP_Proxy:
    def __init__(self, client_addr, server_addr):
        self.client_addr = client_addr
        self.server_addr = server_addr
        self.c2p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.c2p.bind(client_addr)
        self.p2s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    def IO(self):
        try:
            while True:
                message, c_addr = self.c2p.recvfrom(1024)
                print("[[Message from client]]", message, c_addr, "\n")
                self.p2s.sendto(message, self.server_addr)
                data, s_addr = self.p2s.recvfrom(1024)
                print("[[Message from server]]", data, s_addr, "\n")
                self.c2p.sendto(data, c_addr)
        except KeyboardInterrupt:
            print("Exiting")

def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-client_ip", default="localhost", action="store")
    parser.add_argument("-client_port", action="store", type=int)
    parser.add_argument("-server_ip", action="store")
    parser.add_argument("-server_port", action="store", type=int)
    args = parser.parse_args()
    return args

def main():
    args = arguments()
    client_addr = (args.client_ip, args.client_port)
    server_addr = (args.server_ip, args.server_port)
    proxy = UDP_Proxy(client_addr, server_addr)
    proxy.IO()


if __name__ == "__main__":
    main()