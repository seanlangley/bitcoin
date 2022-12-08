from dataclasses import dataclass
from abc import ABC, abstractmethod
from typing import Dict
import time
import ipaddress
from hashlib import sha256

MAGICS = {
    'main': b'\xf9\xbe\xb4\xd9',
    'test': b'\x0b\x11\x09\x07',
}

def do_checksum(data) -> bytes:
  return sha256(sha256(data).digest()).digest()[:4]

@dataclass
class Command(ABC):
  @property
  @abstractmethod
  def command(self) -> str:
    pass

  @classmethod
  @abstractmethod
  def from_bytes(cls, data: bytes):
    pass

  @abstractmethod
  def __bytes__(self):
    pass

  @abstractmethod
  def __str__(self):
    pass


class Packet:
  def __init__(self, message: Command):
    self.payload = message
    self.headers = Headers(
        command=message.command,
        payload_size=len(bytes(self.payload)),
        checksum=do_checksum(bytes(self.payload)),
    )

  def __bytes__(self):
    return bytes(self.headers) + bytes(self.payload)

  def __str__(self):
    return str(self.headers) + str(self.payload)

  @classmethod
  def from_bytes(cls, data: bytes):
    headers = Headers.from_bytes(data[:24])
    payload = data[24:24 + headers.payload_size]
    if do_checksum(payload) != headers.checksum:
      print(f"Checksum failed for headers:\n{headers}")
      return cls(message=VerackMessage())
    command = headers.command
    if command not in command_map:
      print(f"Command not implemented: {command}")
      return cls(message=VerackMessage())
    return cls(message=command_map[command].from_bytes(payload))


@dataclass
class GetBlocks(Command):
  version: int = 70015
  hash_count: int = 1
  header: bytes = bytes.fromhex(
      '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c')
  stop_hash: bytes = bytes.fromhex('')

  @property
  def command(self):
    return "getblocks"

  def __bytes__(self):
    msg = b''
    msg += self.version.to_bytes(4, "little")
    msg += self.hash_count.to_bytes(1, "little")
    msg += sha256(self.header).digest()
    msg += b'\x00' * 32
    return msg

  def __str__(self):
    return f"""
    version:      {self.version}
    hash_count:   {self.hash_count}
    header:       {self.header.hex(' ')}
    stop_hash:    {self.stop_hash}
  """

  @classmethod
  def from_bytes(cls, data):
    return cls()


class VerackMessage(Command):
  @property
  def command(self):
    return "verack"

  def __bytes__(self) -> bytes:
    return b''

  def __str__(self) -> str:
    return ''

  @classmethod
  def from_bytes(cls, data):
    return cls()

class SendHeadersMessage(Command):
  @property
  def command(self):
    return "sendheaders"

  def __bytes__(self) -> bytes:
    return b''

  def __str__(self) -> str:
    return ''

  @classmethod
  def from_bytes(cls, data):
    return cls()

class InvMessage(Command):
  @property
  def command(self):
    return "inv"
  def __bytes__(self):
    return b""
  def __str__(self):
    return ""
  @classmethod
  def from_bytes(cls, data):
    return cls()

@dataclass
class VersionMessage(Command):
  version: int = 70015
  svc: int = 0
  timestamp: int = int(time.time())
  rx_svc: int = 0
  rx_ip: ipaddress.ip_address = ipaddress.ip_address('::ffff:0.0.0.0')
  rx_port: int = 0
  tx_svc: int = 0
  tx_ip: ipaddress.ip_address = ipaddress.ip_address('::ffff:0.0.0.0')
  tx_port: int = 0
  nonce: int = 0
  user_agent: bytes = b'/my_bitcoin/'
  start_height: int = 0
  relay: bool = False

  @property
  def command(self):
    return "version"

  def __bytes__(self) -> bytes:
    version_msg = b''
    version_msg += int(self.version).to_bytes(4, "little", signed=True)
    version_msg += int(self.svc).to_bytes(8, "little")
    version_msg += int(self.timestamp).to_bytes(8, "little", signed=True)
    version_msg += int(self.rx_svc).to_bytes(8, "little")
    version_msg += self.rx_ip.packed
    version_msg += self.rx_port.to_bytes(2, "big")
    version_msg += int(self.tx_svc).to_bytes(8, "little")
    version_msg += self.tx_ip.packed
    version_msg += self.tx_port.to_bytes(2, "big")
    version_msg += self.nonce.to_bytes(8, "little")
    version_msg += int(len(self.user_agent)).to_bytes(1, "little")
    version_msg += self.user_agent
    version_msg += self.start_height.to_bytes(4, "little", signed=True)
    version_msg += int(self.relay).to_bytes(1, "little")
    return version_msg

  @classmethod
  def from_bytes(cls, data: bytes):
    new_msg = cls()
    new_msg.version = int.from_bytes(data[:4], "little")
    new_msg.svc = int.from_bytes(data[4:12], "little")
    new_msg.timestamp = int.from_bytes(data[12:20], "little")
    new_msg.rx_svc = int.from_bytes(data[20:28], "little")
    new_msg.rx_ip = ipaddress.ip_address(data[28:44])
    new_msg.rx_port = int.from_bytes(data[44:46], "little")
    new_msg.tx_svc = int.from_bytes(data[46:54], "little")
    new_msg.tx_ip = ipaddress.ip_address(data[54:70])
    new_msg.tx_port = int.from_bytes(data[70:72], "little")
    new_msg.nonce = int.from_bytes(data[72:80], "little")
    user_agent_bytes = data[80]
    new_msg.user_agent = data[81:81 + user_agent_bytes]
    new_msg.start_height = int.from_bytes(
        data[81 + user_agent_bytes:85 + user_agent_bytes], "little")
    new_msg.relay = bool(data[85 + user_agent_bytes: 86 + user_agent_bytes])
    return new_msg

  def __str__(self):
    return f"""
    version:      {self.version}
    services:     {self.svc}
    timestamp:    {self.timestamp}
    rx_services:  {self.rx_svc}
    rx_ip:        {self.rx_ip}
    rx_port:      {self.rx_port}
    tx_services:  {self.tx_svc}
    tx_ip:        {self.tx_ip}
    tx_port:      {self.tx_port}
    nonce:        {self.nonce}
    user_agent:   {self.user_agent}
    start_heght:  {self.start_height}
    relay:        {self.relay}
  """


@dataclass
class Headers:
  command: str
  payload_size: int
  checksum: bytes
  magic: bytes = MAGICS['main']

  @classmethod
  def from_bytes(cls, data):
    return cls(
        magic=data[:4],
        command=data[4:16].decode().rstrip('\x00'),
        payload_size=int.from_bytes(data[16:20], "little"),
        checksum=data[20:24]
    )

  def __bytes__(self):
    msg = b''
    msg += self.magic
    assert len(self.command) < 13
    msg += bytes(self.command, 'utf-8') + b'\x00' * (12 - len(self.command))
    msg += self.payload_size.to_bytes(4, "little")
    msg += self.checksum
    return msg

  def __str__(self):
    return f"""
    magic:        {self.magic.hex(' ')}
    command:      {self.command}
    payload_size: {self.payload_size}
    checksum:     {self.checksum.hex(' ')}
  """

command_map: Dict[str, Command] = {
  'version': VersionMessage,
  "verack": VerackMessage,
  "getblocks": GetBlocks,
  "sendheaders": SendHeadersMessage,
  "inv": InvMessage,
}
