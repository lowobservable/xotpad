# xotpad

X.25 PAD for XOT.

## Features

Okay, so this is just a prototype for now... the goal is to create a cross-platform user space
[PAD](https://en.wikipedia.org/wiki/Packet_assembler/disassembler)
allowing access to X.25 networks using XOT described in
[RFC 1613](https://www.rfc-editor.org/rfc/rfc1613.html).

  - [x] User space X.25 over TCP (XOT)
      - [x] Modulo 8
      - [x] Modulo 128
      - [ ] Flow control parameter negotiation (packet and window size)
  - [ ] Interactive _Triple-X_ PAD (X.3, X.28 and X.29)
  - [ ] Host PAD providing access to local processes
  - [ ] DNS-based X.25 address resolution

## Usage

### Quick Start

To connect to a host:

```
xotpad -g xot.trysteropac.net 73741100
```

To start an interactive X.28 PAD, and call the same host:

<pre>
<b>xotpad -g xot.trysteropac.net</b>
* <b>call 73741100</b>
...
<kbd>Ctrl+P</kbd>
* <b>exit</b>
</pre>

Use <kbd>Ctrl+P</kbd> to recall the PAD, this is similar to the `telnet` <kbd>Ctrl+]</kbd> sequence.

To exit the interactive PAD, use the `exit` command.

By default, the interactive PAD will _not_ accept incoming calls. To listen for, and accept, incoming calls:

```
xotpad -g xot.trysteropac.net -L
```

Incoming calls will be automatically accepted, assuming the PAD is free.
