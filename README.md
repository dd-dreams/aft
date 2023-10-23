# <p align="center">aft<br>advanced file transferring program<br>![GitHub Workflow Status (with event)](https://img.shields.io/github/actions/workflow/status/dd-dreams/aft/.github%2Fworkflows%2Frust.yml)![GitHub release (with filter)](https://img.shields.io/github/v/release/dd-dreams/aft)

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
- No IP self-lookup.

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
    aft sender [--address <address>] [--port <port>] <filename>
    aft receiver [-p <port>]
    aft download -a <address> [-p <port>]
    aft server [-p <port>]
    aft <mode> [options ...]

Options:
    -a --address ADDRESS        Address to connect to.
    -p --port PORT              Port to host the server on.
    -i --identifier IDENTIFIER  Identifier to find the receiver. Used only when its not P2P.
    -v --verbose VERBOSE        Verbose level. Default is 1 (warnings only). Range 1-3.
    -c --config CONFIG          Config location.
    -r --register               Register.
    -v --version                Show version.
```

# Comparisons
This is the section for the people who might ask what is the difference between this program and SFTP or rsync.
Well, on first hand, there isn't much of a difference. This program and the other two use great encryption algorithms;
are fast, and reliable (well, at least `aft` tries to be). SFTP and rsync are both great program, but they also have their issues.
SFTP for example does not feature transfer-continuation if the connection is dropped (built in). And rsync can be a little complex for some
people.

Both program are excellent, and each one has its own unique benefits, as `aft`.
