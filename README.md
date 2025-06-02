
# UDP FS - VS Code Extension

## Introduction

**UDP FS** is a Visual Studio Code extension that implements a remote file system using a custom UDP-based protocol. It is designed as an alternative to the "Remote SSH" extension, optimized for **unreliable or high-latency networks** where traditional TCP connections may not be ideal.

### Key Features

- Uses **UDP** instead of TCP for improved resilience in unstable network conditions  
- Employs **AES encryption** for secure traffic  
- Requires a custom **UDP server** running on the target machine

---

## How to Compile and Run the UDP Server
~~~
cd vs_udp/
make
~~~
!! edit config.txt to define your own key string !!
~~~
./server
~~~

Run it in tmux/screen session to make it persistent


## How-to config VScode using settings.json ###
~~~
{
  "udpfs.hostname": "<your hostname here>",
  "udpfs.key": "<your secret key here - must match the server's key>"
}
~~~
