
# UDP FS - VS Code Extension

## Introduction

**UDP FS** is a Visual Studio Code extension that implements a remote file system using a custom UDP-based protocol. It is designed as an alternative to the "Remote SSH" extension, optimized for **unreliable or high-latency networks** where traditional TCP connections may not be ideal.

### Key Features

- Uses **UDP** instead of TCP for improved resilience in unstable network conditions  
- Employs **AES encryption** for secure traffic  
- Requires a custom **UDP server** running on the target machine
- Unlike SSH connections that might require a "Reload Window" after network interruptions, UDP FS Provider allows you to continue editing opened files even if network issues occur.

---

## How to Compile and Run the UDP Server
First install dependencies:

Debian/Ubuntu:
~~~
sudo apt update
sudo apt install build-essential libssl-dev
~~~

RedHat/Centos:
~~~
sudo dnf group install "Development Tools"
sudo dnf install openssl-devel
~~~

Build server:
~~~
git clone https://github.com/niliand/vscode_remote_udp.git
cd vscode_remote_udp/vs_udp/
make
~~~
!! edit **config.txt** to define your own key string !!

Run server:
~~~
./server
~~~

Run it in tmux/screen session to make it persistent

### Add firewall rule for UDP port 9022
If needed - add firewall config

Ubuntu/Debian:
~~~
sudo ufw allow 9022/udp
~~~

RHEL/CentOS/Fedora:
~~~
sudo firewall-cmd --permanent --add-port=9022/udp
sudo firewall-cmd --reload
~~~




## How-to config VScode using settings.json ###
Open Command Palette (Ctrl+P or Ctrl+Cmd+P). Find "Preferences: Open User Settings (JSON)" and add following lines:
~~~
{
  ...
  "udpfs.hostname": "<your hostname here>",
  "udpfs.key": "<your secret key here - must match the server's key>"
}
~~~

## How to use extension
- You can install extension from the Extension Store or using vsix file (e.g. vs_plugin/udp-fs-provider-*.vsix).
- In VSCode select Extensions, either find "Remote UDP FS Provide" in the list, or Select [...] icon at the top and item "Install from VSIX..."
- Edit your configuration file and add fields listed above (hostname and key)
- Find and click UDPFS icon in the left pane
- Alternatively Open Command Palette (Ctrl+P or Ctrl+Cmd+P)
- Find command "**UDP FS: Open File**" or "**UDP FS: Open Folder**"
- Enter URI with prefix udpfs:// e.g. for folder: udpfs:///home/username/my_project/
- The "**UDP FS: Search Text in Files**" command helps you find text within files.
- NOTE: Add search excludes to skip search in unrelated folders. In Command Palette find "Preferences: Open User Settings (JSON)" and add exludes like:
~~~
    "search.exclude": {
        "**/.angular": true,
        "**/node_modules": true
    }
~~~

