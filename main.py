import socket
from queue import Queue
import threading
from bitcoin.commands import Packet, VerackMessage, VersionMessage, GetBlocks, Headers, command_map

def main():
  node = BitcoinNode()
  node.handshake()
  node.get_inventory()

class BitcoinNode:
  def __init__(self):
    self.data_queue = Queue()
    self.port = 8333
    hosts = ["mainnet.programmingbitcoin.com", "185.187.169.75"]
    self.socket = socket.create_connection((hosts[0], self.port))
    threading.Thread(target=self.rx_loop).start()

  def rx_loop(self):
    data_buf = b''
    headers = None
    while True:
      data_buf += self.socket.recv(4096)
      while True:
        if not headers and len(data_buf) >= 24:
          headers = Headers.from_bytes(data_buf[:24])
          print(f"RX:\n {headers}")
        if (not headers and len(data_buf) < 24) or \
          (headers and len(data_buf) - 24 < headers.payload_size):
          break
        self.data_queue.put(Packet.from_bytes(data_buf[:headers.payload_size + 24]))
        data_buf = data_buf[headers.payload_size + 24:]
        headers = None

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
      msg = self.data_queue.get()
      self.data_queue.task_done()
      if msg.headers.command == command:
        break

  def get_inventory(self) -> None:
    block_msg = Packet(GetBlocks())
    print(block_msg)
    self.socket.sendall(bytes(block_msg))
    self.wait_for("inv")

  def handshake(self) -> None:
    self.send_version()
    self.wait_for("version")
    self.send_verack()
    self.wait_for("verack")

if __name__ == "__main__":
  main()
