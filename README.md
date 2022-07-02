# xotpad

X.25 PAD for XOT.

## Features

Okay, so this is just a prototype for now... the goal is to create a cross-platform user space
[PAD](https://en.wikipedia.org/wiki/Packet_assembler/disassembler)
allowing access to X.25 networks using XOT described in
[RFC 1613](https://www.rfc-editor.org/rfc/rfc1613.html).

  - [ ] Interactive _Triple-X_ PAD (X.3, X.28 and X.29)
  - [ ] Host PAD providing access to local processes
  - [ ] DNS-based X.25 address resolution

## Usage

For now, set these environment variables:

```
export X121_ADDRESS=111111
export XOT_GATEWAY=...
```

To connect to a host:

```
xotpad 222222
```

To start an interactive PAD:

```
xotpad
```

By default, the interactive PAD will _not_ listen for incoming calls. To listen for
incoming calls:

```
xotpad -L
```

Finally, to provide a host PAD:

```
xotpad -l
```
