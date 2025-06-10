import * as vscode from 'vscode';
import * as dgram from 'dgram';
import { Buffer } from 'buffer';
import * as crypto from 'crypto';
import { controller } from './ExtensionController';

type PendingRequest = {
    resolve: (value?: any) => void;
    reject: (reason?: any) => void;
    type: 'void' | 'buffer';
};

interface MultiReqData {
    seqNo: number;
    buffer: Buffer
};


interface SearchResult {
    uri: vscode.Uri;
    line: number;
    match: string;
};

const FAVORITES_KEY = 'udpfs.favorites';

export function activate(context: vscode.ExtensionContext) {
    console.log('UDP File System Provider is now active!');
    const udpFs = new UdpFileSystemProvider();
    context.subscriptions.push(
        vscode.workspace.registerFileSystemProvider('udpfs', udpFs, { isReadonly: false })
    );

    // Helper to parse and normalize user input into a valid udpfs URI
    function parseUdpfsUri(input: string | undefined): vscode.Uri | undefined {
        if (!input) return undefined;
        const normalized = input.startsWith('udpfs://') ? input : `udpfs://${input}`;
        try {
            return vscode.Uri.parse(normalized);
        } catch (e) {
            vscode.window.showErrorMessage(`Invalid URI: ${normalized}`);
            return undefined;
        }
    }

    context.subscriptions.push(
        vscode.commands.registerCommand("udpfs.openFile", async () => {
            const uriInput = await vscode.window.showInputBox({ prompt: "Enter file path" });
            const uri = parseUdpfsUri(uriInput);
            if (!uri) return;

            try {
                await vscode.commands.executeCommand("vscode.open", uri);
            } catch (err: any) {
                vscode.window.showErrorMessage(`Failed to open file: ${err.message || err}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('udpfs.openRootFolder', async () => {
            try {
                const uriInput = await vscode.window.showInputBox({
                    prompt: 'Enter folder path'
                });

                if (!uriInput) {
                    vscode.window.showWarningMessage('No path entered.');
                    return;
                }

                const uri = parseUdpfsUri(uriInput); // Use your helper here
                if (!uri) return;

                controller.setFolderPath(uri.path)
                //UdpFileSystemProvider.rootFolder = uri.path;
                console.log(`#### rootFolder=${controller.getFolderPath()}`);

                //await vscode.commands.executeCommand("vscode.openFolder", uri);

                // const currentFavorites = context.globalState.get<string[]>(FAVORITES_KEY, []);
                // if (!currentFavorites.includes(uri.toString())) {
                //     await context.globalState.update(FAVORITES_KEY, [...currentFavorites, uri.toString()]);
                // } 

                vscode.workspace.updateWorkspaceFolders(0, 0, {
                    uri,
                    name: `UDPFS: ${uri.path}`
                });

                vscode.commands.executeCommand('workbench.view.explorer');
            } catch (err: any) {
                vscode.window.showErrorMessage(`Failed to open folder: ${err.message || err}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('udpfs.searchText', async () => {

            if (!controller.getFolderPath()) {
                vscode.window.showErrorMessage(`UDP FS: Folder is not opened`);
                return;
            }

            const pattern = await vscode.window.showInputBox({
                prompt: 'Enter search text or leave empty to search files'
            });

            const mask = await vscode.window.showInputBox({
                prompt: 'Enter file mask (e.g. *.txt)',
                value: '*'
            });
            if (!mask) return;

            const results = await udpFs.searchTextInUdpfs(pattern ?? '', mask);
            showSearchResultsInWebview(results, pattern ?? '');
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('udpfs.findDefinition', async () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                const selection = editor.selection;
                const selectedText = editor.document.getText(selection);

                const results = await udpFs.searchDefinitionInUdpfs(selectedText);
                if (results.length == 1) {
                    const [definition, path, pattern] = results[0].split('\t');
                    const uri = 'udpfs://' + controller.getFolderPath() + '/' + path;
                    const patStr = pattern.replace(/^\/\^?/, '').replace(/\$?\/;".*$/, '');
                    openFileAtSymbol(vscode.Uri.parse(uri), patStr);

                } else {
                    showDefinitionResultsInWebview(results, selectedText);
                }

                //vscode.window.showInformationMessage(`Selected: ${selectedText}`);
            }
        })
    );

    // const savedFavorites = context.globalState.get<string[]>(FAVORITES_KEY, []);
    // for (const uriString of savedFavorites) {
    //     const uri = vscode.Uri.parse(uriString);
    //     vscode.workspace.updateWorkspaceFolders(
    //         vscode.workspace.workspaceFolders ? vscode.workspace.workspaceFolders.length : 0,
    //         0,
    //         { uri, name: uri.authority }
    //     );
    // }

    const configChangeDisposable = vscode.workspace.onDidChangeConfiguration(event => {
        if (event.affectsConfiguration('udpfs')) {
            // UDPFS settings were updated.
            const config = vscode.workspace.getConfiguration('udpfs');

            udpFs.updateConfig(config);
        }
    });

    context.subscriptions.push(configChangeDisposable);

    const udpfsSearchView = new UDPFSSearchViewProvider(context, udpFs);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(
            'udpfsSearchView',
            udpfsSearchView
        )
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('udpfs.searchInThisFolder', async (uri: vscode.Uri) => {
            if (uri) {
                vscode.commands.executeCommand('workbench.view.udpfsSearchView');
                vscode.commands.executeCommand('udpfsSearchView.focus');
                udpfsSearchView.setSearchFolder(uri.path);
            } else {
                const uriInput = await vscode.window.showInputBox({
                    prompt: 'Enter folder'
                });

                if (!uriInput) {
                    vscode.window.showWarningMessage('No path entered.');
                    return;
                }
                vscode.commands.executeCommand('workbench.view.udpfsSearchView');
                vscode.commands.executeCommand('udpfsSearchView.focus');
                udpfsSearchView.setSearchFolder(uriInput);

            }
        })
    );

    //vscode.workspace.registerFileSearchProvider('udpfs', new UdpfsFileSearchProvider(udpFs));

    // context.subscriptions.push(
    //vscode.workspace.registerTextSearchProvider(scheme, textSearchProvider)
    // );

    console.log('VS Code API version:', vscode.version);

    // Add button to status bar
    // const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left);
    // statusBarItem.text = '📁 Open UDP FS';
    // statusBarItem.command = 'udpfs.openRootFolder';
    // statusBarItem.tooltip = 'Open UDP File System Root Folder';
    // statusBarItem.show();
    // context.subscriptions.push(statusBarItem);
}

export function deactivate() {
    console.log('UDP File System Provider is now deactivated!');
    // Clean up if needed
}

class UdpFileSystemProvider implements vscode.FileSystemProvider {
    //private udpServer: dgram.Socket;
    private udpClient: dgram.Socket;

    private readonly version = 1; // Protocol version
    private readonly HEADER_SIZE = 265; // Fixed header size
    private readonly MAX_PACKET_SIZE = 1024;

    private readonly READ_FILE = 0;
    private readonly WRITE_FILE = 1;
    private readonly DELETE_FILE = 2;
    private readonly LIST_FILES = 3;
    private readonly FILE_INFO = 4;
    private readonly CREATE_DIRECTORY = 5;
    private readonly RENAME_FILE = 6;
    private readonly SEARCH_FILES = 7;
    private readonly SEARCH_DEFINITION = 8;

    private readonly SERVER_PORT = 9022;
    private SERVER_HOST = '127.0.0.1';
    private readonly TIMEOUT_MS = 5000;

    // Flags
    private readonly END_OF_TRANSMISSION_FLAG = 0x01;
    private readonly ERROR_FLAG = 0x02;
    private readonly FIRST_DATA = 0x04;
    private readonly CASE_SENSITIVE = 0x08;
    private readonly WHOLE_WORD = 0x10;
    private readonly REGEX_WORD = 0x20;
    private readonly SEQ_NO = 0x40;

    private iv = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex'); // 16-byte IV
    private key!: Buffer;

    private _reqId = 1;

    //public static rootFolder?: string;

    private _onDidChangeFile = new vscode.EventEmitter<vscode.FileChangeEvent[]>();
    readonly onDidChangeFile: vscode.Event<vscode.FileChangeEvent[]> = this._onDidChangeFile.event;
    // Then call this._onDidChangeFile.fire(...) when files change

    private pendingRequests = new Map<number, PendingRequest>();

    private pendingMulti = new Map<number, {
        resolve: (data: MultiReqData[]) => void;
        reject: (err: Error) => void;
        chunks: MultiReqData[];
    }>();

    private writeRequests = new Map<number, Buffer[]>();

    constructor() {
        const config = vscode.workspace.getConfiguration('udpfs');
        this.updateConfig(config);

        //this.udpServer = dgram.createSocket('udp4');
        this.udpClient = dgram.createSocket('udp4');

        // this.udpServer.on('message', (msg, rinfo) => {
        //     console.log(`UDP Server got: ${msg} from ${rinfo.address}:${rinfo.port}`);
        //     // Handle incoming UDP messages for file SERVER_PORToperations here
        // });

        // this.udpServer.bind(41234, () => {
        //     console.log('UDP Server listening on port 41234');
        // });

        this.udpClient.on('message', this.onClientMessage);
    }

    public updateConfig(config: vscode.WorkspaceConfiguration) {
        const hostname: string = config.get<string>('hostname') ?? 'localhost';
        const password = config.get<string>('key') ?? 'default key';
        this.key = crypto.createHash('sha256').update(password).digest(); // 32-byte key

        this.SERVER_HOST = hostname;
    }

    private getReqId() {
        const res = this._reqId;
        this._reqId = this._reqId + 1;
        if (this._reqId > 60000) {
            this._reqId = 1;
        }
        return res;
    }

    private encrypt(data: Buffer): Buffer {
        const cipher = crypto.createCipheriv('aes-256-cbc', this.key, this.iv);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        return encrypted;
    }

    private decrypt(encrypted: Buffer): Buffer {
        const decipher = crypto.createDecipheriv('aes-256-cbc', this.key, this.iv);
        const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
        return decrypted;
    }

    private onClientMessage = (msg: Buffer, rinfo: dgram.RemoteInfo) => {
        msg = this.decrypt(msg);
        const type = msg.readUInt8(1);
        const flags = msg.readUInt16BE(2);
        const reqId = msg.readUInt16BE(261);
        //console.log(`UDP Client received: ${msg.length} bytes from ${rinfo.address}:${rinfo.port}, type=${type}, reqId=${reqId} flags=${flags}`);

        if (flags & this.ERROR_FLAG) {
            const packet = this.parsePacket(msg);
            const errorMessage = packet.payload.toString('utf8', 0, packet.payload.length - 1);
            if (type !== this.FILE_INFO && type !== this.READ_FILE) {
                vscode.window.showErrorMessage(`UDP FS Error: ${errorMessage}`);
            }

            const pending = this.pendingRequests.get(reqId);
            if (pending) {
                this.pendingRequests.delete(reqId);
                pending.reject(new Error(errorMessage));
            }
            return;

        }

        if (type === this.READ_FILE || type === this.LIST_FILES || type === this.SEARCH_FILES || type === this.SEARCH_DEFINITION) {
            const pending = this.pendingMulti.get(reqId);
            const packet = this.parsePacket(msg);
            if (pending) {
                if (!pending.chunks.find(obj => obj.seqNo === packet.seqNo)) {
                    pending.chunks.push({ seqNo: packet.seqNo, buffer: packet.payload });
                }

                if (packet.flags & this.END_OF_TRANSMISSION_FLAG) { // LAST_PACKET flag

                    if (type === this.READ_FILE) {
                        // re-request missing packets
                        const res = this.readFileCheckRerequest(reqId, packet.uri, pending.chunks);
                        if (res) {
                            pending.resolve(pending.chunks);
                            this.pendingMulti.delete(reqId);
                        }
                    } else if (type === this.LIST_FILES) {
                        // re-request missing packets
                        const res = this.readDirectoryCheckRerequest(reqId, packet.uri, pending.chunks);
                        if (res) {
                            pending.resolve(pending.chunks);
                            this.pendingMulti.delete(reqId);
                        }
                    } else {
                        pending.resolve(pending.chunks);
                        this.pendingMulti.delete(reqId);
                    }
                }
            } else {
                console.log(`Unexpected multi response with reqId=${reqId}`);
            }
        } else {

            if (type === this.WRITE_FILE && (flags & this.SEQ_NO)) {
                // request to re-send packets for writing
                this.writeFileResend(reqId, msg);
                return;
            }

            const resolver = this.pendingRequests.get(reqId);
            if (resolver) {
                if (resolver.type === 'void') {
                    resolver.resolve(); // no payload
                } else {
                    resolver.resolve(msg); // pass buffer
                }
                this.pendingRequests.delete(reqId);
            } else {
                console.log(`Unexpected response with reqId=${reqId}`);
            }
        }
    };

    // -- Required FS Provider methods --

    notifyFileChanged(uri: vscode.Uri) {
        const event: vscode.FileChangeEvent = {
            type: vscode.FileChangeType.Changed,
            uri: uri
        };
        // Fire event with an array of one FileChangeEvent
        this._onDidChangeFile.fire([event]);
    }

    watch(uri: vscode.Uri, options: { recursive: boolean; excludes: string[]; }): vscode.Disposable {
        console.log('watch called for', uri.toString());
        // Implement file watching over UDP if your protocol supports it, otherwise return dummy
        return new vscode.Disposable(() => { });
    }

    stat(uri: vscode.Uri): vscode.FileStat | Thenable<vscode.FileStat> {
        console.log('stat called for', uri.toString());

        return this.sendRequestStat(uri).then((buffer) => {
            const packet = this.parsePacket(buffer);
            const fileInfo = this.parseFileInfo(packet.payload);

            return {
                type: fileInfo.type as vscode.FileType, // === 1 ? vscode.FileType.File : vscode.FileType.Directory,
                size: fileInfo.size,
                ctime: fileInfo.ctime.getTime(),
                mtime: fileInfo.mtime.getTime(),
            };
        }).catch((err) => {
            console.error('FileNotFound: Error getting file stat:', (err as Error).message, uri.path);
            //throw err; // Re-throw to propagate error to caller
            throw vscode.FileSystemError.FileNotFound(uri);
        });

    }

    readDirectory(uri: vscode.Uri): [string, vscode.FileType][] | Thenable<[string, vscode.FileType][]> {
        console.log('readDirectory called for', uri.toString());

        // set rootFolder
        if (!controller.getFolderPath()) {
            controller.setFolderPath(uri.path);
            console.log(`####2 rootFolder=${controller.getFolderPath()}`);
        } else {
            const path = uri.path;
            if (path.length < controller.getFolderPath().length) {
                console.log(`##### was rootFolder=${controller.getFolderPath()} ===> ${path}`);
                controller.setFolderPath(path);
            }
        }

        return this.sendRequestReadDir(uri).then(chunks => {

            const itemSize = 34; // list_info size
            const items: [name: string, type: vscode.FileType][] = [];

            let seqNo = 0;
            chunks.sort((a, b) => a.seqNo - b.seqNo);
            for (const chunk of chunks) {

                //const numFiles = packet.length / itemSize;
                if (chunk.seqNo != seqNo) {
                    console.error(`Read DIR: Wrong seqNo: ${chunk.seqNo} != ${seqNo}`);
                    throw vscode.FileSystemError.Unavailable(`Unable to read directory: ${uri.toString()}`);
                }
                seqNo = seqNo + 1;

                let offset = 0;
                const totalItems = chunk.buffer.readUInt8(offset);
                offset += 1;

                for (let i = 0; i < totalItems; i++) {
                    if (offset + 2 > chunk.buffer.length) {
                        throw new Error("Buffer ended unexpectedly while reading item header");
                    }

                    const fileType = chunk.buffer.readUInt8(offset);
                    offset += 1;

                    const nameLen = chunk.buffer.readUInt8(offset);
                    offset += 1;

                    if (offset + nameLen > chunk.buffer.length) {
                        throw new Error("Buffer ended unexpectedly while reading filename");
                    }

                    const name: string = chunk.buffer.toString("utf8", offset, offset + nameLen);
                    offset += nameLen;

                    items.push([name, fileType]);
                }
            }

            return items;
        });
    }

    createDirectory(uri: vscode.Uri): void | Thenable<void> {
        console.log('createDirectory called for', uri.toString());
        return this.sendCreateDirectoryReq(uri).then(() => {

        }).catch((err) => {
            console.error('createDirectory failed: ', (err as Error).message);
            //throw err; // Re-throw to propagate error to caller
            throw vscode.FileSystemError.Unavailable(uri);
        });
    }

    readFile(uri: vscode.Uri): Uint8Array | Thenable<Uint8Array> {
        console.log('readFile called for', uri.toString());

        return this.sendRequestRead(uri).then(chunks => {
            const total = chunks.reduce((acc, buf) => acc + buf.buffer.length, 0);
            console.log(`READ chunks=${chunks.length}, total=${total}`);
            const result = new Uint8Array(total);
            let offset = 0;
            let seqNo = 0;
            chunks.sort((a, b) => a.seqNo - b.seqNo);
            for (const chunk of chunks) {
                if (chunk.seqNo != seqNo) {
                    console.error(`Read File: Wrong seqNo: ${chunk.seqNo} != ${seqNo}`);
                    throw vscode.FileSystemError.Unavailable(`Cannot read file: ${uri.toString()}`);
                }
                seqNo = seqNo + 1;
                result.set(chunk.buffer, offset);
                offset += chunk.buffer.length;
            }

            return result;
        });
    }

    private sleep(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    private async sendAllPackets(packets: Buffer[]) {
        // Send all packets
        let seqNo = 0;
        for (const pkt of packets) {
            this.udpClient.send(this.encrypt(pkt), this.SERVER_PORT, this.SERVER_HOST, (err) => {
                if (err) {
                    console.error('UDP send error:', err);
                    vscode.window.showErrorMessage(`Failed to write file: ${err.message}`);
                }
            });

            seqNo = seqNo + 1;

            if (seqNo % 30 === 0) {
                await this.sleep(30); // 30ms delay
            }
        }

        // duplicate last packet:
        setTimeout(() => {
            const pkt = packets[packets.length - 1];
            this.udpClient.send(this.encrypt(pkt), this.SERVER_PORT, this.SERVER_HOST);
        }, 300);        
    }

    writeFile(uri: vscode.Uri, content: Uint8Array, options: { create: boolean; overwrite: boolean; }): void | Thenable<void> {
        console.log('writeFile called for', uri.toString());

        const MAX_PAYLOAD_SIZE = 1024 - this.HEADER_SIZE - 32; // 1024 bytes - header size - space for encoding
        const version = 1;
        const type = this.WRITE_FILE;

        const uriStr = uri.path;
        const uriBuf = Buffer.alloc(255); // padded URI field
        Buffer.from(uriStr).copy(uriBuf); // auto-pads with zeros

        const reqId = this.getReqId();
        let seqNo = 0;

        const packets: Buffer[] = [];

        if (options.create && !content.length) {
            let flags = 0;
            flags += this.END_OF_TRANSMISSION_FLAG;

            flags += this.FIRST_DATA;

            // Create the header
            const header = Buffer.alloc(this.HEADER_SIZE);
            header.writeUInt8(version, 0);                    // version
            header.writeUInt8(type, 1);                       // type
            header.writeUInt16BE(flags, 2);                   // flags
            uriBuf.copy(header, 4);                           // uri (255 bytes)
            header.writeUInt16BE(0, 259);                // payload length
            header.writeUInt16BE(reqId, 261);
            header.writeUInt16BE(seqNo, 263);

            packets.push(header);
        }

        for (let offset = 0; offset < content.length; offset += MAX_PAYLOAD_SIZE) {
            const isLast = offset + MAX_PAYLOAD_SIZE >= content.length;
            let flags = 0;

            if (isLast) {
                flags += this.END_OF_TRANSMISSION_FLAG;
            }

            if (offset == 0) {
                // first packet
                flags += this.FIRST_DATA;
            }

            const chunk = content.slice(offset, offset + MAX_PAYLOAD_SIZE);
            const length = chunk.length;

            // Create the header
            const header = Buffer.alloc(this.HEADER_SIZE);
            header.writeUInt8(version, 0);                    // version
            header.writeUInt8(type, 1);                       // type
            header.writeUInt16BE(flags, 2);                   // flags
            uriBuf.copy(header, 4);                           // uri (255 bytes)
            header.writeUInt16BE(length, 259);                // payload length
            header.writeUInt16BE(reqId, 261);
            header.writeUInt16BE(seqNo, 263);

            seqNo = seqNo + 1;

            const packet = Buffer.concat([header, chunk]);    // full packet
            packets.push(packet);
        }

        this.writeRequests.set(reqId, packets);

        // Send all packets
        this.sendAllPackets(packets);

        // Wait for single final ACK (using pendingRequests)
        return new Promise<void>((resolve, reject) => {
            this.pendingRequests.set(reqId, {
                resolve,
                reject,
                type: 'void',
            });

            // Timeout to reject if no reply
            setTimeout(() => {
                if (this.writeRequests.has(reqId)) {
                    this.writeRequests.delete(reqId);
                }

                if (this.pendingRequests.has(reqId)) {
                    this.pendingRequests.delete(reqId);
                    reject(new Error('Timeout waiting for writeFile ACK'));
                }
            }, 5000 + content.length / 300); // emperical timeout
        });

    }

    delete(uri: vscode.Uri, options: { recursive: boolean; }): void | Thenable<void> {
        console.log('delete called for', uri.toString());
        return this.sendDeleteReq(uri).then(() => {

        }).catch((err) => {
            console.error('createDirectory failed: ', (err as Error).message);
            //throw err; // Re-throw to propagate error to caller
            throw vscode.FileSystemError.Unavailable(uri);
        });
    }

    rename(oldUri: vscode.Uri, newUri: vscode.Uri, options: { overwrite: boolean; }): void | Thenable<void> {
        console.log('rename called for', oldUri.toString(), newUri.toString());
        return this.sendRenameReq(oldUri, newUri).then(() => {

        }).catch((err) => {
            console.error('Rename failed: ', (err as Error).message);
            //throw err; // Re-throw to propagate error to caller
            throw vscode.FileSystemError.Unavailable(newUri);
        });
    }

    private bufferToNullTerminatedString(buffer: Buffer, encoding: BufferEncoding = 'utf8'): string {
        const nullTerminatorIndex = buffer.indexOf(0);

        if (nullTerminatorIndex === -1) {
            // If no null terminator is found, treat the entire buffer as the string
            return buffer.toString(encoding);
        } else {
            // Decode the buffer up to the null terminator
            return buffer.subarray(0, nullTerminatorIndex).toString(encoding);
        }
    }

    parsePacket(buffer: Buffer) {
        if (buffer.length < this.HEADER_SIZE) throw new Error("Packet too small: " + buffer.length + " bytes");

        const version = buffer.readUInt8(0);
        const type = buffer.readUInt8(1);
        const flags = buffer.readUInt16BE(2);
        const uriBuf = buffer.subarray(4, 259); // 255 bytes
        const nullTerminatorIndex = uriBuf.indexOf(0x00);
        const uri = uriBuf.toString('utf8', 0, nullTerminatorIndex !== -1 ? nullTerminatorIndex : 255);
        const length = buffer.readUInt16BE(259);
        const reqId = buffer.readUInt16BE(261);
        const seqNo = buffer.readUInt16BE(263);
        const payload = buffer.subarray(this.HEADER_SIZE, this.HEADER_SIZE + length);

        //console.log(`Parsed packet, size: ${buffer.length}, type=${type}, flags=${flags}, reqId=${reqId}, length=${length}, uri=${uri}`);

        return { version, type, flags, uri, length, reqId, seqNo, payload };
    }

    parseFileInfo(buffer: Buffer) {
        //console.log('Parsing file info packet of size:', buffer.length);
        if (buffer.length < 45) throw new Error("Buffer too small for file_info: " + buffer.length + " bytes, expected at least 45 bytes");

        const size = buffer.readUInt32BE(0);
        const type = buffer.readUInt8(4);
        const ctimeStr = buffer.toString('utf8', 5, 25).replace(/\0.*$/, '');
        const mtimeStr = buffer.toString('utf8', 25, 45).replace(/\0.*$/, '');

        const ctime = new Date(ctimeStr);
        const mtime = new Date(mtimeStr);

        if (isNaN(ctime.getTime())) {
            throw new Error(`Invalid ctime string: "${ctimeStr}"`);
        }
        if (isNaN(mtime.getTime())) {
            throw new Error(`Invalid mtime string: "${mtimeStr}"`);
        }

        return { size, type, ctime, mtime };
    }

    buildUriBuffer(uri: vscode.Uri): Buffer {
        const uriString = uri.path; // or uri.fsPath
        const uriUtf8 = Buffer.from(uriString, 'utf8');

        if (uriUtf8.length >= 255) {
            throw new Error(`URI is too long: ${uriUtf8.length} bytes (max 254 for null termination)`);
        }

        const fixedBuffer = Buffer.alloc(255); // filled with null bytes (0x00)
        uriUtf8.copy(fixedBuffer); // copies starting at offset 0 (default)

        return fixedBuffer;
    }

    private writeFileResend(reqId: number, msg: Buffer) {
        const packet = this.parsePacket(msg);
        const num = packet.length / 2;
        let offset = 0;
        if (!this.writeRequests.has(reqId)) {
            console.log(`ERROR: no such reqId=${reqId} in writeRequests`);
            return;
        }
        const packets = this.writeRequests.get(reqId);
        if (!packets) {
            console.log(`ERROR: can't get reqId=${reqId} in writeRequests`);
            return;
        }
        for (let i = 0; i < num; i++) {
            const seqNo = packet.payload.readUInt16BE(offset); offset += 2;

            if (seqNo < packets.length) {
                const pkt = packets[seqNo];
                let flags = this.SEQ_NO;
                if (i == (num - 1)) {
                    // the last one
                    flags += this.END_OF_TRANSMISSION_FLAG;
                }
                pkt.writeUInt16BE(flags, 2); // flags
                this.udpClient.send(this.encrypt(pkt), this.SERVER_PORT, this.SERVER_HOST);
            }

        }
    }

    // return true to process chunks, false - new request sent
    private readFileCheckRerequest(reqId: number, uriStr: string, chunks: MultiReqData[]): boolean {
        const existingSequences = new Set<number>();
        let maxSequence = 0;

        for (const item of chunks) {
            existingSequences.add(item.seqNo);

            if (item.seqNo > maxSequence) {
                maxSequence = item.seqNo;
            }
        }

        const missingNumbers: number[] = [];
        for (let i = 0; i <= maxSequence; i++) {
            if (!existingSequences.has(i)) {
                missingNumbers.push(i);
            }
        }

        if (missingNumbers.length == 0 || missingNumbers.length > 300) {
            console.log(`READ missingNumbers.length=${missingNumbers.length}, OK for ${uriStr}`);
            return true; // all present or too much missing
        }

        // send request
        const buffer = Buffer.alloc(this.HEADER_SIZE + missingNumbers.length * 2); // Allocate exact size

        // Fill header fields
        let offset = 0;
        buffer.writeUInt8(this.version, offset++);            // version
        buffer.writeUInt8(this.READ_FILE, offset++);               // type
        buffer.writeUInt16BE(this.SEQ_NO, offset); offset += 2; // flags (big-endian)

        // Write URI string into buffer
        const uriBytes = Buffer.from(uriStr, 'utf8');
        uriBytes.copy(buffer, offset);
        offset += 255; // move past URI (rest will be zero-padded automatically)

        // Write length (can be updated to include payload later)
        buffer.writeUInt16BE(missingNumbers.length * 2, offset); offset += 2;

        buffer.writeUInt16BE(reqId, offset); offset += 2;
        buffer.writeUInt16BE(0, offset); offset += 2; // seq no

        for (const num of missingNumbers) {
            buffer.writeUInt16BE(num, offset); offset += 2; // seq no
            //console.log('Send MISS: ', num);
        }

        // Send packet
        this.udpClient.send(this.encrypt(buffer), this.SERVER_PORT, this.SERVER_HOST, (err) => {
            if (err) {
                return true; // to process chunks
            }
        });

        return false;
    }

    // return true to process chunks, false - new request sent
    private readDirectoryCheckRerequest(reqId: number, uriStr: string, chunks: MultiReqData[]): boolean {
        const existingSequences = new Set<number>();
        let maxSequence = 0;

        for (const item of chunks) {
            existingSequences.add(item.seqNo);

            if (item.seqNo > maxSequence) {
                maxSequence = item.seqNo;
            }
        }

        const missingNumbers: number[] = [];
        for (let i = 0; i <= maxSequence; i++) {
            if (!existingSequences.has(i)) {
                missingNumbers.push(i);
            }
        }

        if (missingNumbers.length == 0 || missingNumbers.length > 300) {
            //console.log(`READ-DIR missingNumbers.length=${missingNumbers.length}, OK`);
            return true; // all present or too much missing
        }

        // send request
        const buffer = Buffer.alloc(this.HEADER_SIZE + missingNumbers.length * 2); // Allocate exact size

        // Fill header fields
        let offset = 0;
        buffer.writeUInt8(this.version, offset++);            // version
        buffer.writeUInt8(this.LIST_FILES, offset++);               // type
        buffer.writeUInt16BE(this.SEQ_NO, offset); offset += 2; // flags (big-endian)

        // Write URI string into buffer
        const uriBytes = Buffer.from(uriStr, 'utf8');
        uriBytes.copy(buffer, offset);
        offset += 255; // move past URI (rest will be zero-padded automatically)

        // Write length (can be updated to include payload later)
        buffer.writeUInt16BE(missingNumbers.length * 2, offset); offset += 2;

        buffer.writeUInt16BE(reqId, offset); offset += 2;
        buffer.writeUInt16BE(0, offset); offset += 2; // seq no

        for (const num of missingNumbers) {
            buffer.writeUInt16BE(num, offset); offset += 2; // seq no
            //console.log('Send MISS: ', num);
        }

        // Send packet
        this.udpClient.send(this.encrypt(buffer), this.SERVER_PORT, this.SERVER_HOST, (err) => {
            if (err) {
                return true; // to process chunks
            }
        });

        return false;
    }


    private readTimeoutHandler(reqId: number, packets: number, reject: (reason?: any) => void) {
        console.log(`readTimeoutHandler reqId=${reqId}, packets=${packets}`);
        if (this.pendingMulti.has(reqId)) {
            const pending = this.pendingMulti.get(reqId);

            console.log(`readTimeoutHandler pending=${pending ? 'YES' : 'NO'}, currCount=${pending?.chunks.length}`);

            if (pending) {
                const currCount = pending.chunks.length;

                if (currCount > packets) {
                    // if packets still arriving - reset timeout
                    setTimeout(() => { this.readTimeoutHandler(reqId, currCount, reject); }, 5000);
                } else {
                    console.log(`readTimeoutHandler reqId=${reqId}, TIMEOUT!!`);
                    this.pendingMulti.delete(reqId);
                    reject(new Error('UDP read timeout'));
                }
            }
        }
    }

    private sendRequestRead(uri: vscode.Uri): Promise<MultiReqData[]> {
        const buffer = Buffer.alloc(this.HEADER_SIZE); // Allocate exact size

        const reqId = this.getReqId();

        // Fill header fields
        let offset = 0;
        buffer.writeUInt8(this.version, offset++);            // version
        buffer.writeUInt8(this.READ_FILE, offset++);               // type
        buffer.writeUInt16BE(0, offset); offset += 2; // flags (big-endian)

        // Write URI string into buffer
        const uriStr = uri.path; // or uri.fsPath
        const uriBytes = Buffer.from(uriStr, 'utf8');
        if (uriBytes.length > 255) throw new Error("URI too long");
        uriBytes.copy(buffer, offset);
        offset += 255; // move past URI (rest will be zero-padded automatically)

        // Write length (can be updated to include payload later)
        buffer.writeUInt16BE(0, offset); offset += 2;

        buffer.writeUInt16BE(reqId, offset); offset += 2;

        return new Promise((resolve, reject) => {

            this.pendingMulti.set(reqId, {
                resolve,
                reject,
                chunks: []
            });

            // Send packet
            this.udpClient.send(this.encrypt(buffer), this.SERVER_PORT, this.SERVER_HOST, (err) => {
                if (err) {
                    return reject(err);
                }
            });

            setTimeout(() => { this.readTimeoutHandler(reqId, 0, reject); }, 5000);
        });
    }

    private sendRequestReadDir(uri: vscode.Uri): Promise<MultiReqData[]> {
        const buffer = Buffer.alloc(this.HEADER_SIZE); // Allocate exact size

        const reqId = this.getReqId();

        // Fill header fields
        let offset = 0;
        buffer.writeUInt8(this.version, offset++);            // version
        buffer.writeUInt8(this.LIST_FILES, offset++);               // type
        buffer.writeUInt16BE(0, offset); offset += 2; // flags (big-endian)

        // Write URI string into buffer
        const uriStr = uri.path; // or uri.fsPath
        const uriBytes = Buffer.from(uriStr, 'utf8');
        if (uriBytes.length > 255) throw new Error("URI too long");
        uriBytes.copy(buffer, offset);
        offset += 255; // move past URI (rest will be zero-padded automatically)

        // Write length (can be updated to include payload later)
        buffer.writeUInt16BE(0, offset); offset += 2;

        buffer.writeUInt16BE(reqId, offset); offset += 2;

        return new Promise((resolve, reject) => {

            this.pendingMulti.set(reqId, {
                resolve,
                reject,
                chunks: []
            });

            // Send packet
            this.udpClient.send(this.encrypt(buffer), this.SERVER_PORT, this.SERVER_HOST, (err) => {
                if (err) {
                    return reject(err);
                }
            });

            setTimeout(() => { this.readTimeoutHandler(reqId, 0, reject); }, 5000);
        });
    }

    sendRequestStat(uri: vscode.Uri): Promise<Buffer> {

        return new Promise((resolve, reject) => {
            const reqId = this.getReqId();
            this.pendingRequests.set(reqId, {
                resolve,
                reject,
                type: 'buffer',
            });

            // Send the initial request
            const buffer = Buffer.alloc(this.HEADER_SIZE); // Allocate exact size

            // Fill header fields
            let offset = 0;
            buffer.writeUInt8(this.version, offset++);            // version
            buffer.writeUInt8(this.FILE_INFO, offset++);               // type
            buffer.writeUInt16BE(0, offset); offset += 2; // flags (big-endian)

            // Write URI string into buffer
            const uriStr = uri.path; // or uri.fsPath
            const uriBytes = Buffer.from(uriStr, 'utf8');
            if (uriBytes.length > 255) throw new Error("URI too long");
            uriBytes.copy(buffer, offset);
            offset += 255; // move past URI (rest will be zero-padded automatically)

            // Write length (can be updated to include payload later)
            buffer.writeUInt16BE(0, offset); offset += 2;
            buffer.writeUInt16BE(reqId, offset); offset += 2;

            // Send packet
            this.udpClient.send(this.encrypt(buffer), this.SERVER_PORT, this.SERVER_HOST, (err) => {
                if (err) {
                    return reject(err);
                }
            });

            setTimeout(() => {
                this.pendingRequests.delete(reqId);
                reject(new Error('UDP request stat() timed out for ' + uri.path));
            }, 3000);

        });
    }

    private sendCreateDirectoryReq(uri: vscode.Uri): Promise<void> {

        return new Promise((resolve, reject) => {
            const reqId = this.getReqId();
            this.pendingRequests.set(reqId, {
                resolve,
                reject,
                type: 'void',
            });

            // Send the initial request
            const buffer = Buffer.alloc(this.HEADER_SIZE); // Allocate exact size

            // Fill header fields
            let offset = 0;
            buffer.writeUInt8(this.version, offset++);            // version
            buffer.writeUInt8(this.CREATE_DIRECTORY, offset++);               // type
            buffer.writeUInt16BE(0, offset); offset += 2; // flags (big-endian)

            // Write URI string into buffer
            const uriStr = uri.path; // or uri.fsPath
            const uriBytes = Buffer.from(uriStr, 'utf8');
            if (uriBytes.length > 255) throw new Error("URI too long");
            uriBytes.copy(buffer, offset);
            offset += 255; // move past URI (rest will be zero-padded automatically)

            // Write length (can be updated to include payload later)
            buffer.writeUInt16BE(0, offset); offset += 2;
            buffer.writeUInt16BE(reqId, offset); offset += 2;

            // Send packet
            this.udpClient.send(this.encrypt(buffer), this.SERVER_PORT, this.SERVER_HOST, (err) => {
                if (err) {
                    return reject(err);
                }
            });

            setTimeout(() => {
                this.pendingRequests.delete(reqId);
                reject(new Error('UDP request timed out'));
            }, 3000);

        });
    }

    private sendDeleteReq(uri: vscode.Uri): Promise<void> {

        return new Promise((resolve, reject) => {
            const reqId = this.getReqId();
            this.pendingRequests.set(reqId, {
                resolve,
                reject,
                type: 'void',
            });

            // Send the initial request
            const buffer = Buffer.alloc(this.HEADER_SIZE); // Allocate exact size

            // Fill header fields
            let offset = 0;
            buffer.writeUInt8(this.version, offset++);            // version
            buffer.writeUInt8(this.DELETE_FILE, offset++);               // type
            buffer.writeUInt16BE(0, offset); offset += 2; // flags (big-endian)

            // Write URI string into buffer
            const uriStr = uri.path; // or uri.fsPath
            const uriBytes = Buffer.from(uriStr, 'utf8');
            if (uriBytes.length > 255) throw new Error("URI too long");
            uriBytes.copy(buffer, offset);
            offset += 255; // move past URI (rest will be zero-padded automatically)

            // Write length (can be updated to include payload later)
            buffer.writeUInt16BE(0, offset); offset += 2;
            buffer.writeUInt16BE(reqId, offset); offset += 2;

            // Send packet
            this.udpClient.send(this.encrypt(buffer), this.SERVER_PORT, this.SERVER_HOST, (err) => {
                if (err) {
                    return reject(err);
                }
            });

            setTimeout(() => {
                this.pendingRequests.delete(reqId);
                reject(new Error('UDP request timed out'));
            }, 3000);

        });
    }

    private sendRenameReq(uriOld: vscode.Uri, uriNew: vscode.Uri): Promise<void> {

        return new Promise((resolve, reject) => {
            const reqId = this.getReqId();
            this.pendingRequests.set(reqId, {
                resolve,
                reject,
                type: 'void',
            });

            // Send the initial request
            const buffer = Buffer.alloc(this.HEADER_SIZE); // Allocate exact size

            // Fill header fields
            let offset = 0;
            buffer.writeUInt8(this.version, offset++);            // version
            buffer.writeUInt8(this.RENAME_FILE, offset++);               // type
            buffer.writeUInt16BE(0, offset); offset += 2; // flags (big-endian)

            // Write URI string into buffer
            const uriStr = uriOld.path; // or uri.fsPath
            const uriBytes = Buffer.from(uriStr, 'utf8');
            if (uriBytes.length > 255) throw new Error("URI too long");
            uriBytes.copy(buffer, offset);
            offset += 255; // move past URI (rest will be zero-padded automatically)

            const uriStrNew = uriNew.path; // or uri.fsPath
            const uriBytesNew = Buffer.from(uriStrNew, 'utf8');

            // Write length (can be updated to include payload later)
            buffer.writeUInt16BE(uriBytesNew.length, offset); offset += 2;
            buffer.writeUInt16BE(reqId, offset); offset += 2;
            buffer.writeUInt16BE(0, offset); offset += 2;  // seq no

            const packet = Buffer.concat([buffer, uriBytesNew]);    // full packet

            // Send packet
            this.udpClient.send(this.encrypt(packet), this.SERVER_PORT, this.SERVER_HOST, (err) => {
                if (err) {
                    return reject(err);
                }
            });

            setTimeout(() => {
                this.pendingRequests.delete(reqId);
                reject(new Error('UDP request timed out'));
            }, 3000);

        });
    }

    public sendSearchFilesReq(pattern: string, mask: string, excludes: string[], caseSensitive: boolean, wholeWord: boolean, regex: boolean): Promise<MultiReqData[]> {
        const buffer = Buffer.alloc(this.HEADER_SIZE); // Allocate exact size

        const reqId = this.getReqId();

        // Fill header fields
        let offset = 0;
        buffer.writeUInt8(this.version, offset++);            // version
        buffer.writeUInt8(this.SEARCH_FILES, offset++);               // type
        let flags = 0;
        if (caseSensitive)
            flags += this.CASE_SENSITIVE;
        if (wholeWord)
            flags += this.WHOLE_WORD;
        if (regex)
            flags += this.REGEX_WORD;
        buffer.writeUInt16BE(flags, offset); offset += 2; // flags (big-endian)

        // Write URI string into buffer
        const uriStr = controller.getFolderPath();
        const uriBytes = Buffer.from(uriStr, 'utf8');
        uriBytes.copy(buffer, offset);
        offset += 255; // move past URI (rest will be zero-padded automatically)

        const patternBytes = Buffer.from(pattern, 'utf8');
        const maskBytes = Buffer.from(mask, 'utf8');

        const patternLenBuf = Buffer.alloc(1, patternBytes.length);
        const maskLenBuf = Buffer.alloc(1, maskBytes.length);

        buffer.writeUInt16BE(patternBytes.length + maskBytes.length + 2, offset); offset += 2; // length
        buffer.writeUInt16BE(reqId, offset); offset += 2;
        buffer.writeUInt16BE(0, offset); offset += 2;  // seq no

        const packetTmp = Buffer.concat([buffer, maskLenBuf, maskBytes, patternLenBuf, patternBytes]);
        let remainSize = this.MAX_PACKET_SIZE - packetTmp.length;

        const buffers = excludes.map(str => {
            const strBuf = Buffer.from(str, 'utf8');
            if (strBuf.length <= 255 && remainSize > (strBuf.length + 1)) {
                const lenBuf = Buffer.from([strBuf.length]); // 1-byte length
                remainSize += strBuf.length + 1;
                return Buffer.concat([lenBuf, strBuf]);
            } else {
                return Buffer.alloc(0);
            }
        });

        let excBuffer = Buffer.concat(buffers);
        excBuffer = Buffer.concat([excBuffer, Buffer.alloc(1, 0)]);

        const packet = Buffer.concat([packetTmp, excBuffer]);

        return new Promise((resolve, reject) => {

            this.pendingMulti.set(reqId, {
                resolve,
                reject,
                chunks: []
            });

            // Send packet
            this.udpClient.send(this.encrypt(packet), this.SERVER_PORT, this.SERVER_HOST, (err) => {
                if (err) {
                    return reject(err);
                }
            });

            setTimeout(() => {
                if (this.pendingMulti.has(reqId)) {
                    this.pendingMulti.delete(reqId);
                    reject(new Error('UDP search files timeout'));
                }
            }, 60000);
        });
    }

    public sendSearchDefinitionReq(pattern: string): Promise<MultiReqData[]> {
        const buffer = Buffer.alloc(this.HEADER_SIZE); // Allocate exact size

        const reqId = this.getReqId();

        // Fill header fields
        let offset = 0;
        buffer.writeUInt8(this.version, offset++);            // version
        buffer.writeUInt8(this.SEARCH_DEFINITION, offset++);               // type
        let flags = 0;
        buffer.writeUInt16BE(flags, offset); offset += 2; // flags (big-endian)

        // Write URI string into buffer
        const uriStr = controller.getFolderPath();
        const uriBytes = Buffer.from(uriStr, 'utf8');
        uriBytes.copy(buffer, offset);
        offset += 255; // move past URI (rest will be zero-padded automatically)

        const patternBytes = Buffer.from(pattern, 'utf8');
        const patternLenBuf = Buffer.alloc(1, patternBytes.length);

        buffer.writeUInt16BE(patternBytes.length + 2, offset); offset += 2; // length
        buffer.writeUInt16BE(reqId, offset); offset += 2;
        buffer.writeUInt16BE(0, offset); offset += 2;  // seq no

        const packet = Buffer.concat([buffer, patternLenBuf, patternBytes]);

        return new Promise((resolve, reject) => {

            this.pendingMulti.set(reqId, {
                resolve,
                reject,
                chunks: []
            });

            // Send packet
            this.udpClient.send(this.encrypt(packet), this.SERVER_PORT, this.SERVER_HOST, (err) => {
                if (err) {
                    return reject(err);
                }
            });

            setTimeout(() => {
                if (this.pendingMulti.has(reqId)) {
                    this.pendingMulti.delete(reqId);
                    reject(new Error('UDP search definition timeout'));
                }
            }, 7000);
        });
    }


    public searchTextInUdpfs(pattern: string, mask: string,
        caseSensitive: boolean = true, wholeWord: boolean = false, regex: boolean = false): Promise<SearchResult[]> {

        if (!controller.getFolderPath()) {
            vscode.window.showErrorMessage(`UDP FS: Folder is not opened`);
            return Promise.resolve([]);
        }

        const filesExclude = vscode.workspace.getConfiguration().get<{ [key: string]: boolean }>('files.exclude') ?? {};
        const searchExclude = vscode.workspace.getConfiguration().get<{ [key: string]: boolean }>('search.exclude') ?? {};

        const excludes = { ...filesExclude, ...searchExclude };
        const excludesArr: string[] = Object.entries(excludes)
            .filter(([_, enabled]) => enabled)
            .map(([pattern]) => pattern);

        return this.sendSearchFilesReq(pattern, mask, excludesArr, caseSensitive, wholeWord, regex).then(chunks => {
            const items: SearchResult[] = [];

            // no need to sort search result
            //chunks.sort((a, b) => a.seqNo - b.seqNo);
            for (const chunk of chunks) {
                // total(1), path_len (1), path (1..255), line no (2), line_len (1), line (1..255) 
                let offset = 0;
                const totalItems = chunk.buffer.readUInt8(offset);
                offset += 1;

                for (let i = 0; i < totalItems; i++) {
                    const pathLen = chunk.buffer.readUInt8(offset); offset += 1;

                    if (offset + pathLen > chunk.buffer.length) {
                        throw new Error("Buffer ended unexpectedly while reading filename");
                    }

                    const path: string = chunk.buffer.toString("utf8", offset, offset + pathLen);
                    offset += pathLen;

                    const lineNo = chunk.buffer.readUInt16BE(offset); offset += 2;
                    const lineLen = chunk.buffer.readUInt8(offset); offset += 1;

                    let lineStr: string = '';

                    if (lineLen > 0) {
                        lineStr = chunk.buffer.toString("utf8", offset, offset + lineLen);
                        offset += lineLen;
                    }

                    //console.log(`SEARCH: ${path}:${lineNo}  lineLen=${lineLen} line=${lineStr}`);
                    items.push({ uri: vscode.Uri.parse('udpfs://' + controller.getFolderPath() + '/' + path), line: lineNo, match: lineStr });
                }
            }

            return items;
        });
    }

    public searchDefinitionInUdpfs(pattern: string): Promise<string[]> {

        if (!controller.getFolderPath()) {
            vscode.window.showErrorMessage(`UDP FS: Folder is not opened`);
            return Promise.resolve([]);
        }

        return this.sendSearchDefinitionReq(pattern).then(chunks => {
            const items: string[] = [];

            // no need to sort search result
            for (const chunk of chunks) {
                // total(1), text_len (1), text (1..255)
                let offset = 0;
                const totalItems = chunk.buffer.readUInt8(offset);
                offset += 1;

                for (let i = 0; i < totalItems; i++) {
                    const lineLen = chunk.buffer.readUInt8(offset); offset += 1;

                    if (offset + lineLen > chunk.buffer.length) {
                        throw new Error("Buffer ended unexpectedly while reading filename");
                    }

                    const line: string = chunk.buffer.toString("utf8", offset, offset + lineLen);
                    offset += lineLen;

                    //console.log(`DEFINITION: ${line}`);
                    items.push(line);
                }
            }

            return items;
        });

    }



} //UdpFileSystemProvider

async function openFileAtSymbol(uri: vscode.Uri, pattern: string) {
    const doc = await vscode.workspace.openTextDocument(uri);
    const editor = await vscode.window.showTextDocument(doc);

    // Remove leading/trailing / and ^$ from the pattern
    //const regex = new RegExp(pattern.replace(/^\/\^?/, '').replace(/\$?\/;".*$/, ''));
    //const regex = new RegExp(pattern);

    //const lineNumber = doc.getText().split('\n').findIndex(line => regex.test(line));
    const lineNumber = doc.getText().split('\n').findIndex(line => line.indexOf(pattern) != -1);
    if (lineNumber >= 0) {
        const position = new vscode.Position(lineNumber, 0);
        editor.selection = new vscode.Selection(position, position);
        editor.revealRange(new vscode.Range(position, position));
    } else {
        vscode.window.showWarningMessage(`Pattern not found in ${uri.fsPath}`);
    }
}

function showDefinitionResultsInWebview(results: string[], pattern: string) {
    const panel = vscode.window.createWebviewPanel(
        'udpfsSearch',
        `Search: "${pattern}"`,
        vscode.ViewColumn.One,
        { enableScripts: true }
    );

    const regex = new RegExp(`(${pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');

    const linksHtml = results.length > 0
        ? results.map(r => {
            const [definition, path, pattern] = r.split('\t');
            const uri = 'udpfs://' + controller.getFolderPath() + '/' + path;
            const patStr = pattern.replace(/^\/\^?/, '').replace(/\$?\/;".*$/, '');

            return `<div>
          <a href="#" onclick="vscode.postMessage({ command: 'open', uri: '${uri}', pattern: '${patStr}' })" >
            ${path} 
          </a> — <code>${escapeHtml(patStr).replace(regex, '<span class="highlight">$1</span>')}</code>
        </div>`
        }
        ).join('')
        : `<p>No matches found.</p>`;

    panel.webview.html = `
    <html>
    <head>
    <style>
        .highlight {
          background-color: var(--vscode-editor-findMatchHighlightBackground, yellow);
          color: inherit;
        }
    </style>
    </head>
    <body>
      <h2>Search Results for <code>${escapeHtml(pattern)}</code></h2>
      ${linksHtml}
      <script>
        const vscode = acquireVsCodeApi();
        document.querySelectorAll('a').forEach(el => {
          el.addEventListener('click', e => {
            e.preventDefault();
          });
        });
      </script>
    </body>
    </html>
  `;

    panel.webview.onDidReceiveMessage(async message => {
        if (message.command === 'open') {
            console.log(` open DEF: uri=${message.uri}, pattern=${message.pattern}`);
            const uri = vscode.Uri.parse(message.uri);
            const pattern = message.pattern;

            await openFileAtSymbol(uri, pattern);
        }
    });

}

function showSearchResultsInWebview(results: SearchResult[], pattern: string) {
    const panel = vscode.window.createWebviewPanel(
        'udpfsSearch',
        `Search: "${pattern}"`,
        vscode.ViewColumn.One,
        { enableScripts: true }
    );

    const regex = new RegExp(`(${pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');

    const linksHtml = results.length > 0
        ? results.map(r =>
            `<div>
          <a href="#" onclick="vscode.postMessage({ command: 'open', uri: '${r.uri.toString()}', line: ${r.line > 0 ? r.line - 1 : 1} })">
            ${r.uri.path.slice(controller.getFolderPath().length + 1)}:${r.line > 0 ? r.line : 1}
          </a> ${r.line > 0 ? '—' : ''} <code>${escapeHtml(r.match).replace(regex, '<span class="highlight">$1</span>')}</code>
        </div>`
        ).join('')
        : `<p>No matches found.</p>`;

    panel.webview.html = `
    <html>
    <head>
    <style>
        .highlight {
          background-color: var(--vscode-editor-findMatchHighlightBackground, yellow);
          color: inherit;
        }
    </style>
    </head>
    <body>
      <h2>Search Results for <code>${escapeHtml(pattern)}</code></h2>
      ${linksHtml}
      <script>
        const vscode = acquireVsCodeApi();
        document.querySelectorAll('a').forEach(el => {
          el.addEventListener('click', e => {
            e.preventDefault();
          });
        });
      </script>
    </body>
    </html>
  `;

    panel.webview.onDidReceiveMessage(async message => {
        if (message.command === 'open') {
            const uri = vscode.Uri.parse(message.uri);
            const pos = new vscode.Position(message.line, 0);
            const doc = await vscode.workspace.openTextDocument(uri);
            await vscode.window.showTextDocument(doc, {
                selection: new vscode.Range(pos, pos)
            });
        }
    });
}

function escapeHtml(text: string): string {
    return text.replace(/[&<>"']/g, m => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[m]!));
}

class UDPFSSearchViewProvider implements vscode.WebviewViewProvider {
    private _view?: vscode.WebviewView;

    constructor(private context: vscode.ExtensionContext, private udpFs: UdpFileSystemProvider) { }

    resolveWebviewView(
        webviewView: vscode.WebviewView,
        _context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken
    ) {
        webviewView.webview.options = {
            enableScripts: true
        };

        this._view = webviewView;

        webviewView.webview.html = this.getHtml(webviewView.webview);

        webviewView.webview.onDidReceiveMessage(message => {
            if (message.command === 'startSearch') {
                const { searchText, fileMask, caseSensitive, wholeWord, regex } = message;

                if (!fileMask) {
                    vscode.window.showErrorMessage(`File mask is empty.`);
                    return;
                }

                if (searchText) {
                    vscode.window.showInformationMessage(`Searching for: ${searchText} in ${fileMask}`);
                } else {
                    vscode.window.showInformationMessage(`Searching for ${fileMask}`);
                }

                if (searchText) {
                    this.startSearch(searchText, fileMask, caseSensitive, wholeWord, regex);
                } else {
                    this.startSearchFiles(fileMask);
                }
            } else if (message.command === 'openFolder') {
                void vscode.commands.executeCommand('udpfs.openRootFolder', ...(message.args || []));
            } else if (message.command === 'openFile') {
                const fileUri = vscode.Uri.parse('udpfs://' + message.path);
                vscode.workspace.openTextDocument(fileUri).then(doc => {
                    vscode.window.showTextDocument(doc).then(editor => {
                        //const pos = new vscode.Position(message.line - 1, 0);
                        //editor.selection = new vscode.Selection(pos, pos);
                        //editor.revealRange(new vscode.Range(pos, pos));
                    });
                });
            }
        });

    }

    public setSearchFolder(folder: string) {
        if (this._view) {
            let _folder = folder;
            if (_folder.length > controller.getFolderPath().length) {
                _folder = _folder.slice(controller.getFolderPath().length + 1) + '/';
            }
            else {
                if (!_folder.endsWith('/'))
                    _folder += '/';
            }
            this._view.webview.postMessage({ command: 'folder', folder: _folder });
        }
    }

    private startSearch(searchText: string, fileMask: string, caseSensitive: boolean, wholeWord: boolean, regex: boolean) {
        // Fire-and-forget async call
        void this.doSearch(searchText, fileMask, caseSensitive, wholeWord, regex);
    }

    private startSearchFiles(fileMask: string) {
        void this.doSearchFiles(fileMask);
    }

    private async doSearch(searchText: string, fileMask: string, caseSensitive: boolean, wholeWord: boolean, regex: boolean) {
        try {
            const results = await this.udpFs.searchTextInUdpfs(searchText ?? '', fileMask, caseSensitive, wholeWord, regex);

            this._view?.webview.postMessage({
                command: 'textSearchFinished'
            });

            showSearchResultsInWebview(results, searchText ?? '');
        } catch (err) {
            this._view?.webview.postMessage({
                command: 'textSearchFinished'
            });

            console.error('Search error:', err);
        }
    }

    private async doSearchFiles(fileMask: string) {
        try {
            const results = await this.udpFs.searchTextInUdpfs('', fileMask, false, false);
            this._view?.webview.postMessage({
                command: 'updateFileList',
                files: results.map(obj => ({
                    path: obj.uri.path,
                    name: obj.uri.path.slice(controller.getFolderPath().length + 1),
                }))
            });
        } catch (err) {
            console.error('Search error:', err);
        }
    }

    private getHtml(webview: vscode.Webview): string {
        return `
<!DOCTYPE html>
<html>
<head>
  <style>
    body {
      background-color: var(--vscode-sideBar-background);
      color: var(--vscode-foreground);
      font-family: var(--vscode-font-family);
      padding: 8px;
    }

input {
  background-color: var(--vscode-input-background);
  color: var(--vscode-input-foreground);
  border: 1px solid var(--vscode-input-border);
  padding: 4px;
  margin-bottom: 8px;
  width: 100%;
  box-sizing: border-box;
}

/* Only the top "Open folder" button should stretch */
button.full-width {
  background-color: var(--vscode-button-background);
  color: var(--vscode-button-foreground);
  border: none;
  padding: 6px;
  width: 100%;
  cursor: pointer;
  box-sizing: border-box;
}

button.full-width:hover {
  background-color: var(--vscode-button-hoverBackground);
}

/* Search container layout */
.search-container {
    display: flex;
    align-items: center;
    gap: 6px;
    background-color: var(--vscode-input-background);
    padding: 0 4px;
    border: 1px solid var(--vscode-input-border);
    border-radius: 4px;
    height: 28px;
    box-sizing: border-box;
    margin-bottom: 8px;
}

.search-container input {
    flex: 1;
    border: none;
    background-color: transparent;
    color: var(--vscode-input-foreground);
    font-size: 13px;
    line-height: 24px;
    padding: 0;
    height: 24px;
    margin: 0;
    outline: none;
    box-sizing: border-box;
}

/* Small toggle buttons */
  .toggle-button {
    background-color: var(--vscode-button-secondaryBackground);
    color: var(--vscode-button-secondaryForeground);
    border: none;
    padding: 2px 6px;
    font-size: 12px;
    cursor: pointer;
    border-radius: 3px;
    height: 24px;
    line-height: 20px;
    display: flex;
    align-items: center;
    justify-content: center;
  }

.toggle-button.active {
  background-color: var(--vscode-button-background);
  color: var(--vscode-button-foreground);
}   

  #fileList {
    list-style: none;
    padding: 0;
  }
  #fileList li {
    margin-bottom: 4px;
  }
  #fileList a {
    color: var(--vscode-textLink-foreground);
    text-decoration: none;
  }
  #fileList a:hover {
    text-decoration: underline;
  }

  .progressBarContainer {
    display: none;
    height: 4px;
    background-color: var(--vscode-editor-background);
    overflow: hidden;
    position: relative;
    margin: 10px 0;
  }

  #progressBar {
    height: 100%;
    width: 30%;
    background-color: var(--vscode-progressBar-background, var(--vscode-foreground));
    position: absolute;
    animation: moveBar 1.2s infinite;
  }

  @keyframes moveBar {
    0% {
      left: -30%;
    }
    50% {
      left: 50%;
    }
    100% {
      left: 100%;
    }
  }

  </style>
</head>
<body>
  <button id="openFolderBtn" class="full-width">Open folder</button>
  <br> <br><hr> <br>

<div class="search-container">
  <input id="searchText" placeholder="Search text" />
  <button class="toggle-button" id="caseToggle">Aa</button>
  <button class="toggle-button" id="wordToggle">W</button>
  <button class="toggle-button" id="regexToggle">.*</button>
</div>

  <input id="fileMask" placeholder="File mask (e.g. *.ts)" />
<div class="progressBarContainer" id="progressBarContainerText">
  <div id="progressBar"></div>
</div>  
  <button id="searchTextBtn" class="full-width" onclick="startSearch()">Search text</button>

  <br> <br><hr> <br>
  <input id="fileMask2" placeholder="File mask (e.g. user*)" />
  
<div class="progressBarContainer" id="progressBarContainer">
  <div id="progressBar"></div>
</div>

  <ul id="fileList"></ul>

  <script>
    const vscode = acquireVsCodeApi();

  const caseBtn = document.getElementById('caseToggle');
  const wordBtn = document.getElementById('wordToggle');
  const regexBtn = document.getElementById('regexToggle');

  caseBtn.addEventListener('click', () => {
    caseBtn.classList.toggle('active');
  });

  wordBtn.addEventListener('click', () => {
    wordBtn.classList.toggle('active');
  });    

  regexBtn.addEventListener('click', () => {
    regexBtn.classList.toggle('active');
  }); 

  const openFolderBtn = document.getElementById('openFolderBtn');
  
  openFolderBtn.addEventListener('click', () => {
    vscode.postMessage({ command: 'openFolder' });
  });

    function startSearch() {
      const searchText = document.getElementById('searchText').value;
      const caseSensitive = caseBtn.classList.contains('active');
      const wholeWord = wordBtn.classList.contains('active');
      const regex = regexBtn.classList.contains('active');
      const fileMask = document.getElementById('fileMask').value;
    
      document.getElementById('searchTextBtn').style.display = 'none';
      document.getElementById('progressBarContainerText').style.display = 'block';
      vscode.postMessage({ command: 'startSearch', searchText, fileMask, caseSensitive, wholeWord, regex });
    }

  const inputFiles = document.getElementById('fileMask2');
  let debounceTimeout;

  inputFiles.addEventListener('input', () => {
    clearTimeout(debounceTimeout); // Reset timer on every keystroke

    debounceTimeout = setTimeout(() => {
      const fileMask = inputFiles.value;
      const searchText = '';
      if (fileMask && fileMask.length > 1) {
         document.getElementById('progressBarContainer').style.display = 'block';
         vscode.postMessage({ command: 'startSearch', searchText, fileMask });
      }
    }, 1500); // delay
  });

window.addEventListener('message', event => {
    const message = event.data;
    if (message.command === 'updateFileList') {
      document.getElementById('progressBarContainer').style.display = 'none';
      updateFileList(message.files);
    } else if (message.command === 'folder') {
       const fileMask = document.getElementById('fileMask');
       fileMask.value = message.folder;
    } else if (message.command === 'textSearchFinished') {
      document.getElementById('searchTextBtn').style.display = 'block';
      document.getElementById('progressBarContainerText').style.display = 'none';
    }
  });

  function updateFileList(files) {
    const list = document.getElementById('fileList');
    list.innerHTML = ''; // clear existing

    files.forEach(file => {
      const item = document.createElement('li');

      const link = document.createElement('a');
      link.href = '#';
      link.textContent = file.name;
      link.onclick = () => {
        vscode.postMessage({
          command: 'openFile',
          path: file.path
        });
      };

      item.appendChild(link);
      list.appendChild(item);
    });
  }

  </script>
</body>
</html>
    `;
    }
}
