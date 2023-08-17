# A CLI for establishing NTCP2 connections

## Introduction

`ntcp2-hs` is a CLI that allows you to connect to [I2P](https://geti2p.net/en) nodes



It contains a partial implementation of the [NOISE](https://noiseprotocol.org/) Protocol Framework and enough data structures to establish an [NTCP2](https://geti2p.net/spec/ntcp2) handshake. NTCP2 is a protocol running on top of TCP and provides encrypted connections between I2P Routers. More information can be found in the I2P [Protocol stack chart](https://geti2p.net/en/docs/protocol)



The CLI is tested against [IRE](https://github.com/str4d/ire), an I2P Router implementation written in Rust. This repo provides a patch (`ire.patch`) for IRE which makes it easier to retrieve the necessary information for establishing NTCP2 connections to the router once it's running.



## What it does

NTCP2 uses NOISE for encryption, obfuscation, and key exhange. The exchanged messages also contain NTCP2 specific payloads.



In NOISE terms, the data exchanged during a handshake is the following:

```
XK(s, rs):
  <- s
  ...
  -> e, es
  <- e, ee
  -> s, se
  <-
```

The first message `s` describes the data about the peer already known by the initiator. That is:

- Public Key

- Router Hash (Used as AES Encryption Key)

- AES IV (Initialization Vector)

The next 3 messages exchange ephimeral and static keys. They also contain the NTCP2 specific payload:

```
Alice                           Bob

SessionRequest ------------------->
<------------------- SessionCreated
SessionConfirmed ----------------->
```

This CLI establishes an NTCP2 Handshake to an I2P Router. These are the steps it takes:

- Generates its own static key pair

- Connects to a target router using TCP

- Initializes a NOISE HandshakeState

- Generates a SessionRequest, processes it through NOISE, and sends it to the target node

- Receives a SessionCreated, processes it through NOISE, and parses it

- Generates a dummy SessionConfirmed, processes it through NOISE, and sends it to the target node

The SessionConfirmed message should contain the [RouterInfo](https://geti2p.net/spec/common-structures#routerinfo) of the initiator I2P Router

Since this CLI does not generate a router identity, it sends the bytes `[1, 3, 3, 7]` instead

# Getting started

## IRE

### Building the executable

Clone the IRE repository

```bash
git clone https://github.com/str4d/ire.git
```

Checkout the specific commit on which the patch is based on

```bash
git checkout cf4b146681b48301a0bdf9a37953efd33795a8f8
```

Apply the patch from this repository

```bash
cd ire
patch -p1 < <path/to/ire.patch>
```

Build the cli

```bash
cargo build --release --bin ire --features="cli"
```

### Running

Run with trace logs

```bash
RUST_LOG=ire=trace ./target/release/ire router ./examples/router.toml
```

You should see something like this:

```
[2023-08-17T09:36:32Z INFO  ire::router::builder] Config option router.keyfile not set, creating ephemeral router keys
[2023-08-17T09:36:32Z WARN  ire::router::builder] Config option router.infofile not set, not writing RouterInfo to disk
[2023-08-17T09:36:32Z INFO  ire::router] Our router hash is CMLaqMXK0-MHTSR35VeAiwi0P0aOAlLhyuxrh5xrlVk=
[2023-08-17T09:36:32Z INFO  ire::transport::ntcp] Listening on 127.0.0.1:12345
[2023-08-17T09:36:32Z INFO  ire::transport::ntcp2] Listening on 127.0.0.1:12346
NTCP2 Info:
	Public key: N0CG8qhchDbeq9vK5Vqg0w201g7lKicXiEPaKHsvzW4=
	AES Key (Router Hash): CMLaqMXK0+MHTSR35VeAiwi0P0aOAlLhyuxrh5xrlVk=
	AES IV: pRAL/JsEpz3VR+kM0bDO+Q==
```

The line `[2023-08-17T09:36:32Z INFO ire::transport::ntcp2] Listening on 127.0.0.1:12346` shows the host and port for `NTCP2` connections

Make note of these values:

- Host and Port for NTCP2 connections

- Public key

- Router Hash

- IV (Initialization Vector)

All these values are published by I2P nodes and are necessary to establish NTCP2 connections

## NTCP2-HS

### Building the executable

Clone this repository

```bash
https://github.com/Revanee/ntcp2-handshake.git
```

Build the cli

```bash
cargo build --release --bin ntcp2-hs
```

### Running

While IRE is running, connect to it using `ntcp2-hs` like in the following example:

```bash
./target/release/ntcp2-hs connect localhost 12346 N0CG8qhchDbeq9vK5Vqg0w201g7lKicXiEPaKHsvzW4= WSfnxUcL3DRYF2RE4mFnmQX+7TIDvTkRGLDj7DROBIg= pRAL/JsEpz3VR+kM0bDO+Q==
```

The `connect` subcommand takes the values we got from IRE in order to establish an NTCP2 Handshake as an initiator (Alice in NOISE terms)

```bash
Usage: ntcp2-hs connect <HOST> <PORT> <PEER_PUBLIC_KEY> <PEER_ROUTER_HASH> <PEER_IV>

Arguments:
  <HOST>              The I2P Router's hostname
  <PORT>              The I2P Router's port
  <PEER_PUBLIC_KEY>   Peer's public key in b64
  <PEER_ROUTER_HASH>  Peer's router hash in b64
  <PEER_IV>           Peer's IV in b64
```

### Interpreting the output

#### NTCP2-HS

If all goes well, you should see the following:

- Key generation

- Outgoing connection

- Message and padding exchange

- Handshake complete

An example log should look like this:

```
Generated public key: 8e5b92cd771e0c8e6d22217c728052236cca3491310ebe60ee74da45794bb434
Connecting to localhost:12346
Sending SessionRequest: SessionRequest (id: 2, pad_len: 3, m3p2_len: 20, tsa: 0)
Receiving message of length 64...
Received SessionCreated: SessionCreated (pad_len: 9, ts_b: 1692269402)
Receiving message of length 9...
Received SessionCreated padding: [11, 82, 132, 186, 24, 17, 246, 11, 75]
Sending SessionConfirmed: [1, 3, 3, 7]
Handshake complete!
```

#### IRE

On the IRE side, you should see:

- Incomming connection

- The 3 NOISE messages being exchanged

- An error parsing the SessionConfirmed message

The log should look like this:

```
2023-08-17T10:27:43Z INFO  ire::transport::ntcp2] Incoming connection!
[2023-08-17T10:27:43Z DEBUG ire::transport::ntcp2::handshake] S <- e, es
[2023-08-17T10:27:43Z DEBUG ire::transport::ntcp2::handshake] S -> e, ee
[2023-08-17T10:27:43Z DEBUG ire::transport::ntcp2::handshake] S <- s, se
[2023-08-17T10:27:43Z ERROR ire::transport::ntcp2] Error while listening: Custom { kind: Other, error: "SessionConfirmed parse error: Error { input: [1, 3, 3, 7], code: Complete }" }
```

As noted before, the SessionConfirmed payload being sent is `[1, 3, 3, 7]`, and that value should be visible in the logs
