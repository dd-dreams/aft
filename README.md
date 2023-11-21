# <p align="center">aft<br>![GitHub Workflow Status (with event)](https://img.shields.io/github/actions/workflow/status/dd-dreams/aft/.github%2Fworkflows%2Frust.yml)![GitHub release (with filter)](https://img.shields.io/github/v/release/dd-dreams/aft)

aft (Advanced File Transfer) is a minimal and secure tool for sharing files between two parties easily and efficiently. Works in Windows, Linux and macOS.

# Features
- Encryption.
- Fast.
- Lightweight (on RAM and storage).
- Security is top priority.
- Peer to Peer mode.
- Relay mode.
- Blocking senders.
- No IP self-lookup.
- fail2ban support.

# Modes
There are a couple of modes to use with this program:
## Peer to Peer
The sender is directly connected to the receiver, and the transfer process is happening directly.
## Relay
Allows using a relay instead of two devices connecting to each other directly. It allows a few benefits such as:
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
    aft relay [-p <port>]
    aft <mode> [options ...]

Positional arguments:
    mode

Optional arguments:
    -a --address ADDRESS        Address.
    -p --port PORT              Port.
    -i --identifier IDENTIFIER  Identifier to find the receiver. Used only when its not P2P.
    -v --verbose VERBOSE        Verbose level. Default is 1 (warnings only). Range 1-3.
    -c --config CONFIG          Config location.
    -v --version                Show version.
```

# Installation

## Automatic install
Run the following command to install aft: `curl --proto '=https' -sf https://raw.githubusercontent.com/dd-dreams/aft/master/install.sh | sudo sh -s -- install`.

If you want to modify the config, you can create a new file at your home directory (`%USERPROFILE%` for Windows and `~/` for Unix) within `.aft` directory, named: "config".
Look into `docs/CONFIG.md` to see more.

Run the following command to uninstall aft: `curl --proto '=https' -sf https://raw.githubusercontent.com/dd-dreams/aft/master/install.sh | sudo sh -s -- uninstall`.

## Manual install
Navigate to the [releases](https://github.com/dd-dreams/aft/releases) page and choose your platform.
For Windows you can export the archive contents by double clicking.
For Linux and macOS you can use `gzip` for extracting the contents. `gzip` should be included by default.
Run: `gzip -dN <archive>`. You can export the program anywhere you like, but make sure you add it to PATH so you can easily access it.

### Systemd setup
- Copy the `aft` program into `/usr/local/bin/`.
- Copy `aft-relay.service` into `/etc/systemd/system/`.
- Start the program with: `sudo systemctl start aft-relay`.

Notice that the service requires a new user called `aft`. If you want the service to be ran with root, remove the `User=aft` line, though it's not recommended for security reasons.

This service only runs the relay mode.

## fail2ban setup
- Copy `assets/fail2ban/aft-relay-filter.conf` into `/etc/fail2ban/filter.d/`.
- Copy `assets/fail2ban/aft-relay.conf` into `/etc/fail2ban/jail.d/`
- Restart the service: `sudo systemctl restart fail2ban`

You can modify the bantime and maxretries in `aft-relay.conf`.

### Notice
fail2ban only works on relay mode. fail2ban doesn't work on Windows.

# Building
Building is really simple: `cargo build --release` and the output will be at `target/release/aft`.

# Comparisons
This is the section for the people who might ask what is the difference between this program and SFTP or rsync.
Well, on first hand, there isn't much of a difference. This program and the other two use great encryption algorithms;
are fast, and reliable (well, at least `aft` tries to be). SFTP and rsync are both great program, but they also have their issues.
SFTP for example does not feature transfer-continuation if the connection is dropped (built in). And rsync can be a little complex for some
people.

Both program are excellent, and each one has its own unique benefits, as `aft`.

# License
Licensed under either of:
- Apache License, Version 2.0
- MIT License.
