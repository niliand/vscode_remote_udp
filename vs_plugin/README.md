## Introduction

**UDP FS** is a Visual Studio Code extension that implements a remote file system using a custom UDP-based protocol. It is designed as an alternative to the "Remote SSH" extension, optimized for **unreliable or high-latency networks** where traditional TCP connections may not be ideal.

### Key Features

- Uses **UDP** instead of TCP for improved resilience in unstable network conditions  
- Employs **AES encryption** for secure traffic  
- Requires a custom **UDP server** running on the target machine
- Supports **CTAGS**
- Unlike SSH connections that might require a "Reload Window" after network interruptions, UDP FS Provider doesn't require it

### To install server
- Visit https://github.com/niliand/vscode_remote_udp/ for details

### How to use extension
- Edit your settings.json and add fields listed below (hostname and key)
- Find and click UDPFS icon in the left pane
- Or use Command Palette (Ctrl+P or Ctrl+Cmd+P)
- Find command "**UDP FS: Open File**" or "**UDP FS: Open Folder**"
- Enter URI with prefix udpfs:// e.g. for folder: udpfs:///home/username/my_project/
- The "**UDP FS: Search Text in Files**" command helps you find text within files. To search only for file names, simply leave the search text field blank.
- NOTE: Add search excludes to skip search in unrelated folders. In Command Palette find "Preferences: Open User Settings (JSON)" and add exludes like:
~~~
    "search.exclude": {
        "**/.angular": true,
        "**/node_modules": true
    }
~~~

#### How-to config VScode using settings.json ###
Open Command Palette (Ctrl+P or Ctrl+Cmd+P). Find "Preferences: Open User Settings (JSON)" and add following lines:
~~~
{
  ...
  "udpfs.hostname": "<your hostname here>",
  "udpfs.key": "<your secret key here - must match the server's key>"
}
~~~

### Current restrictions

- Max path limited to 254 symbols (fits the most cases)
- Doesn't support big files over 45 Mb
- Doesn't monitor external file changes; updates made outside the editor won't be reloaded.
- NOTE: it is expected that some operations like open or save file can show error - just try again later. It is due to network loses / delays.

