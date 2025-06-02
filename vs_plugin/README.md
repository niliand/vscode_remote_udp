## Introduction

**UDP FS** is a Visual Studio Code extension that implements a remote file system using a custom UDP-based protocol. It is designed as an alternative to the "Remote SSH" extension, optimized for **unreliable or high-latency networks** where traditional TCP connections may not be ideal.

### Key Features

- Uses **UDP** instead of TCP for improved resilience in unstable network conditions  
- Employs **AES encryption** for secure traffic  
- Requires a custom **UDP server** running on the target machine

### Current restrictions

- Max path limited to 254 symbols (fits the most cases)
- Does not support big files over 45 Mb
- NOTE: it is expected that some operations like read or save file can show error - just try again later. It is due to network loses / delays.

### To install server
- Visit https://github.com/niliand/vscode_remote_udp/ for details