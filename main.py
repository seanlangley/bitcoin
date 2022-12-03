import socket
from bitcoin.commands import Packet, VerackMessage, VersionMessage, GetBlocks, command_map

def main():
  node = BitcoinNode()
  node.handshake()
  node.get_inventory()

class BitcoinNode:
  def __init__(self):
    self.port = 8333
    hosts = ["mainnet.programmingbitcoin.com", "185.187.169.75"]
    self.socket = socket.create_connection((hosts[0], self.port))

  def send_version(self) -> None:
    msg = Packet(VersionMessage())
    print(msg)
    self.socket.sendall(bytes(msg))

  def send_verack(self) -> None:
    verack_msg = Packet(VerackMessage())
    print(verack_msg)
    self.socket.sendall(bytes(verack_msg))

  def wait_for(self, command: command_map.keys()):
    while True:
      data = self.socket.recv(65536)
      msg = Packet.from_bytes(data)
      if msg.headers.command != command:
        continue

  def get_inventory(self) -> None:
    block_msg = Packet(GetBlocks())
    print(block_msg)
    self.socket.sendall(bytes(block_msg))
    self.wait_for("inv")

  def handshake(self) -> None:
    self.send_version()
    data = self.socket.recv(4096)
    print(Packet.from_bytes(data))
    self.send_verack()
    data = self.socket.recv(4096)
    print(Packet.from_bytes(data))

if __name__ == "__main__":
  main()
