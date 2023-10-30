# The aft protocol
`aft` supports two modes: Peer to Peer (P2P) and relay mode.
The transferring process on both modes is basically the same, only the difference is instead of connecting to each other directly (in P2P mode), there is a relay sitting between them. The relay gets very little information, as you will see later.

The main benefit between the two modes is not needing to open a port so you can accept files. Opening a port can be problematic since some ISP's do not allow it because they use NAT, or you just don't want to risk yourself with a port always open on your device. Relay mode also hides your IP from the sender. For example when you accept a file from some stranger, you don't want them to know your IP.

## The protocol - techincal
When the sender connects to some address, it needs to know whether it's a relay or not. So the first thing the sender does is reading 1 byte and checking if it's a relay. If it is, it will initiate relay mode. Otherwise P2P mode.

## Relay mode
The connection between the sender/receiver and the relay is not encrypted by default. It's up to the implementation if to support TLS or not. But, the protocol does not reveal any sensitive information plainly, so encryption is not needed at the start.

### One step - first handshake
The relay needs to know when a client connects to him: if he is the receiver or the sender, so the client writes 1 byte which signals if he is the receiver or the sender.

#### If the client a receiver
The receiver will write his identifier so the sender can know whom to send to. The server will write back a signal whether this identifier is available or not. If it's not, the client will disconnect. After that, the client will wait for a signal to start the file transfer.

#### If the client a sender
The sender will write the receiver's identifier AND his identifier, so the receiver can decide whether to accept him or not. The relay server will check if the receiver's identifier exists (basically if the receiver is online). If it does not, the sender will disconnect.

### Step two - acceptance
Before the second handshake, the receiver receives a signal from the relay server that someone wants to send him a file. The relay server sends to the receiver the sender's identifier AND the sender's SHA-256 hashed IP. The receiver has three options:
- accepting the request, and moving on to the next handshake;
- rejecting the request, and waiting again for a file transfer request;
- blocking the sender, and waiting again for a request.

The relay server doesn't care if the receiver blocked the sender or rejected the request, so the blocking happens on the receiver's side.

Before we discuss the second handshake, we will discuss the first handshake for the receiver in P2P mode:

## P2P mode

### Step one - first handshake
When the sender connects to the receiver, the receiver will write 1 byte indicating he is a receiver and not a relay. After that, they initiate the second handshake (discussed later).

### Step two - acceptance
The receiver should have a SHA-256 hashed password ready (or hashed later) for authentication. When the connection is encrypted, the sender will write his persumed authentication password, which is SHA-256 hashed, and the receiver will compare it to his hash. If they match, the receiver will signal the sender he can start the transfer. Otherwise, they will disconnect from each other.

## Second handshake - public keys exchange
From now on, both modes act in the same way exactly, only that the relay server will forward the requests from the sender to the receiver and otherway.

Once the first handshake is done, AND the receiver accepted the request, we can move to the next handshake, which involves exchanging encryption keys. The receiver will send his public key to the sender/relay. The sender in return will send his public key to the receiver/relay. It's up to the implementation what is the key length. In relay mode, the relay should NOT care what encryption algorithm is used.

From now on, the connection is completely encrypted, and in relay mode the relay has no eyes on the actual content.

## Pre-transfer - metadata
The sender will send information about the file in a JSON format. An example for the JSON can look like the following:
```json
{
	"metadata": {
		"filetype": "<filetype>",
		"filename": "<filename>",
		"size": "<file size in bytes>",
		"modified": "<date>"
	}
}
```
It's up to the implementation what keys-values will exist.
If the receiver accepts the request (he can deny based on the metadata content), the receiver will check if a previous interrupted transfer of the same file occurred. If:
- false: it will send 0 (for the current position).
- true: it will send the current position.

The sender will send the current computed checksum based on the file position. If the receiver wants to continue, the actual transfer will start.

## The transfer
The sender will send **encrypted** chunks of the file. Each chunk will be a fixed size pre-configured on the sender and the receiver/relay sides. When there are no more chunks, the sender will signal that.

## At the end
The sender will send a computed SHA-256 checksum of the file, and the receiver will compare it with his checksum. The sender doesn't care if they match. After all of these stages, both the sender and the receiver will finally disconnect from each-other/relay.

# Note
This file may be updated along the way, for example because of security issues.

The protocol was designed by dd-dreams ([GitHub](https://github.com/dd-dreams "GitHub")).
