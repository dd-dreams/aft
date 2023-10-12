# <p align="center">aft<br>advanced file transferring program<br>![GitHub repo size](https://img.shields.io/github/repo-size/dd-dreams/aft)</p>

aft (Advanced File Transfer) is a minimal and secure tool for sharing files between two parties easily and efficiently. Works in Windows, Linux and macOS.

This program is currently in beta stage.

# Features
- Encryption.
- Fast.
- Lightweight (on RAM and storage).
- Security is top priority.
- Peer to Peer mode.
- Middle server mode.
- Blocking senders.

# Modes
There are a few modes to use with this program:
## P2P (Peer to Peer)
The sender is directly connecting to the receiver, and the transfer process is happening directly.
## Middle Server
Allows using a middle server instead of two devices connecting to each other directly. It allows a few benefits such as:
- No port forward needed on the receiver's end.
- No direct contact between the receiver and the sender.
- Better privacy - no IP sharing.

# Usage
```
aft - file transfer done easily

Usage:
    aft --mode sender --address <address> [--port <port>] <filename>
    aft -m receiver [-p <port>]
    aft -m download -a <address> [-p <port>]
    aft -m server [-p <port>]

Options:
    -m --mode MODE              Run as `sender`, `server`, `receiver` or `download`.
    -a --address ADDRESS        Address to connect to/host on.
    -p --port PORT              Port to host the server on.
    -i --identifier IDENTIFIER  Identifier to find the receiver. Used only when its not P2P.
    -v --verbose VERBOSE        Verbose level. Default is 1 (warnings only). Range 1-3.
    -c --config CONFIG          Config location.
    -r --register REGISTER      Register.
```
