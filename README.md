# TinyP2PC
<img src="https://github.com/brandonvessel/TinyP2PC/raw/master/logo.png" width="200">
TinyP2PC is a basic framework for simple P2P architectures allowing decentralized control of systems using a public and private RSA key system. It handles all the connection and logistics of peer discovery and message transmission while allowing developers to focus on the application of a P2P system. It is designed for almost instant transportation of data to every peer in the net where only RSA verified messages are transmitted and handled.

## Table of Contents

- [Contributing](#contributing-to-tinyp2pc)
- [Start using TinyP2PC](#start-using-TinyP2P)
- [License](#license)


# Contributing to TinyP2PC
Feel free to contribute through pull requests or issues. See the [license section](#license) for more details.

# Start using TinyP2P
TinyP2PC requires 2 things to start compiling:
- gcc
- libssl-dev

They are both installed on Ubuntu/Debian automatically when compiling, but they might have to manually be installed on another OS. This program has difficulty runing on Windows. I would recommend Linux.

You can test the program by running the test.sh file. Make sure to change the value for the origin_peer or your peers will not be able to find one another.

```bash
chmod 777 *
./test.sh
```

To send a message, use this format: '-m TEXT'
The buffer in the process_command will have "TEXT"


# License

All code contributed to this project is subject to the terms and conditions outlined in the [GNU General Public License V3.0](https://www.gnu.org/licenses/gpl-3.0.en.html) which is provided in the form of the LICENSE file.
