import * as vscode from 'vscode';
import * as dgram from 'dgram';
import { Buffer } from 'buffer';
import * as crypto from 'crypto';

type PendingRequest = {
    resolve: (value?: any) => void;
    reject: (reason?: any) => void;
    type: 'void' | 'buffer'; // or use custom request types
};

interface MultiReqData
{
    seqNo: number;
    buffer: Buffer
};

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
            const uriInput = await vscode.window.showInputBox({ prompt: "Enter UDPFS file path" });
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
                    prompt: 'Enter UDPFS folder path'
                });

                if (!uriInput) {
                    vscode.window.showWarningMessage('No path entered.');
                    return;
                }

                const uri = parseUdpfsUri(uriInput); // Use your helper here
                if (!uri) return;

                //await vscode.commands.executeCommand("vscode.openFolder", uri);

                vscode.workspace.updateWorkspaceFolders(0, 0, {
                    uri,
                    name: `UDPFS: ${uri.path}`
                });
            } catch (err: any) {
                vscode.window.showErrorMessage(`Failed to open folder: ${err.message || err}`);
            }
        })
    );


    // Add button to status bar
    const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left);
    statusBarItem.text = '📁 Open UDP FS';
    statusBarItem.command = 'udpfs.openRootFolder';
    statusBarItem.tooltip = 'Open UDP File System Root Folder';
    statusBarItem.show();

    context.subscriptions.push(statusBarItem);
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

    private readonly READ_FILE = 0;
    private readonly WRITE_FILE = 1;
    private readonly DELETE_FILE = 2;
    private readonly LIST_FILES = 3;
    private readonly FILE_INFO = 4;
    private readonly CREATE_DIRECTORY = 5;
    private readonly RENAME_FILE = 6;

    private readonly SERVER_PORT = 9022;
    private SERVER_HOST = '127.0.0.1';
    private readonly TIMEOUT_MS = 5000;

    // Flags
    private readonly END_OF_TRANSMISSION_FLAG = 0x01;
    private readonly ERROR_FLAG = 0x02;
    private readonly FIRST_DATA = 0x04;

    private iv = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex'); // 16-byte IV
    private key: Buffer;

    private _reqId = 1;

    private _onDidChangeFile = new vscode.EventEmitter<vscode.FileChangeEvent[]>();
    readonly onDidChangeFile: vscode.Event<vscode.FileChangeEvent[]> = this._onDidChangeFile.event;
    // Then call this._onDidChangeFile.fire(...) when files change

    private pendingRequests = new Map<number, PendingRequest>();

    private pendingMulti = new Map<number, {
        resolve: (data: MultiReqData[]) => void;
        reject: (err: Error) => void;
        chunks: MultiReqData[];
    }>();

    constructor() {
        const config = vscode.workspace.getConfiguration('udpfs');
        const hostname: string = config.get<string>('hostname') ?? 'localhost';
        const password = config.get<string>('key') ?? 'default key';
        this.key = crypto.createHash('sha256').update(password).digest(); // 32-byte key

        console.log(`password: [${password}]`);
        console.log('key: ', this.key);
        console.log('iv: ', this.iv);

        this.SERVER_HOST = hostname;

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
        console.log(`UDP Client received: ${msg.length} bytes from ${rinfo.address}:${rinfo.port}, type=${type}, reqId=${reqId} flags=${flags}`);

        if (flags & this.ERROR_FLAG) {
            const packet = this.parsePacket(msg);
            const errorMessage = packet.payload.toString('utf8');
            vscode.window.showErrorMessage(`UDP Error: ${errorMessage}`);

            const pending = this.pendingRequests.get(reqId);
            if (pending) {
                this.pendingRequests.delete(reqId);
                pending.reject(new Error(errorMessage));
            }
            return;

        }

        if (type === this.READ_FILE || type === this.LIST_FILES) {
            const pending = this.pendingMulti.get(reqId);
            const packet = this.parsePacket(msg);
            if (pending) {
                pending.chunks.push({seqNo:packet.seqNo, buffer: packet.payload});

                if (packet.flags & this.END_OF_TRANSMISSION_FLAG) { // LAST_PACKET flag
                    console.log('Last packet type: ', type);
                    this.pendingMulti.delete(reqId);
                    pending.resolve(pending.chunks);
                }
            } else {
                console.warn(`Unexpected multi response with reqId=${reqId}`);
            }
        } else {

            const resolver = this.pendingRequests.get(reqId);
            if (resolver) {
                this.pendingRequests.delete(reqId);
                if (resolver.type === 'void') {
                    resolver.resolve(); // no payload
                } else {
                    resolver.resolve(msg); // pass buffer
                }
            } else {
                console.warn(`Unexpected response with reqId=${reqId}`);
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
            console.log('File info:', fileInfo);
            return {
                type: fileInfo.type === 1 ? vscode.FileType.File : vscode.FileType.Directory,
                size: fileInfo.size,
                ctime: fileInfo.ctime.getTime(),
                mtime: fileInfo.mtime.getTime(),
            };
        }).catch((err) => {
            console.error('FileNotFound: Error getting file stat:', (err as Error).message);
            //throw err; // Re-throw to propagate error to caller
            throw vscode.FileSystemError.FileNotFound(uri);
        });

    }

    readDirectory(uri: vscode.Uri): [string, vscode.FileType][] | Thenable<[string, vscode.FileType][]> {
        console.log('readDirectory called for', uri.toString());
        // TODO: Request directory listing over UDP
        return this.sendRequestReadDir(uri).then(chunks => {
            console.log('sendRequestReadDir resolve: num chunks:', chunks.length);
            const itemSize = 34; // list_info size
            const items: [name: string, type: vscode.FileType][] = [];

            let seqNo = 0;
            chunks.sort((a, b) => a.seqNo - b.seqNo);
            for (const chunk of chunks) {
                //const numFiles = packet.length / itemSize;
                if (chunk.seqNo != seqNo) {
                    console.error(`Wrong seqNo: ${chunk.seqNo} != ${seqNo}`);
                    throw vscode.FileSystemError.Unavailable(`Unable to read directory: ${uri.toString()}`);
                }
                seqNo = seqNo + 1;
                

                for (let offset = 0; (offset + itemSize) <= chunk.buffer.length; offset += itemSize) {
                    const type = chunk.buffer.readUInt8(offset);
                    const nameBuf = chunk.buffer.slice(offset + 1, offset + 33);
                    const name = nameBuf.toString('utf8').replace(/\0.*$/, ''); // Remove null terminator and trailing nulls

                    console.log(`file: ${name}, type: ${type}`);

                    items.push([name, type]);
                }
            }

            return items;
        });
        //return [['file.txt', vscode.FileType.File]];
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
            const result = new Uint8Array(total);
            let offset = 0;
            let seqNo = 0;
            chunks.sort((a, b) => a.seqNo - b.seqNo);
            for (const chunk of chunks) {
                if (chunk.seqNo != seqNo) {
                    console.error(`Wrong seqNo: ${chunk.seqNo} != ${seqNo}`);
                    throw vscode.FileSystemError.Unavailable(`Cannot read file: ${uri.toString()}`);
                }
                seqNo = seqNo + 1;
                result.set(chunk.buffer, offset);
                offset += chunk.buffer.length;
            }
            return result;
        });
    }

    writeFile(uri: vscode.Uri, content: Uint8Array, options: { create: boolean; overwrite: boolean; }): void | Thenable<void> {
        console.log('writeFile called for', uri.toString());
        const MAX_PAYLOAD_SIZE = 1024 - 300; // 1024 bytes - header size
        const version = 1;
        const type = this.WRITE_FILE;

        const uriStr = uri.path;
        const uriBuf = Buffer.alloc(255); // padded URI field
        Buffer.from(uriStr).copy(uriBuf); // auto-pads with zeros

        const reqId = this.getReqId();
        let seqNo = 0;

        const packets: Buffer[] = [];

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

        // Send all packets
        for (const pkt of packets) {
            this.udpClient.send(this.encrypt(pkt), this.SERVER_PORT, this.SERVER_HOST, (err) => {
                if (err) {
                    console.error('UDP send error:', err);
                    vscode.window.showErrorMessage(`Failed to write file: ${err.message}`);
                }
            });
        }

        // Wait for single final ACK (using pendingRequests)
        return new Promise<void>((resolve, reject) => {
            this.pendingRequests.set(reqId, {
                resolve,
                reject,
                type: 'void',
            });

            // Timeout to reject if no reply
            setTimeout(() => {
                if (this.pendingRequests.has(reqId)) {
                    this.pendingRequests.delete(reqId);
                    reject(new Error('Timeout waiting for writeFile ACK'));
                }
            }, 3000);
        });

    }

    delete(uri: vscode.Uri, options: { recursive: boolean; }): void | Thenable<void> {
        console.log('delete called for', uri.toString());
        // TODO: Send delete command over UDP
    }

    rename(oldUri: vscode.Uri, newUri: vscode.Uri, options: { overwrite: boolean; }): void | Thenable<void> {
        console.log('rename called for', oldUri.toString(), newUri.toString());
        // TODO: Send rename command over UDP
    }

    parsePacket(buffer: Buffer) {
        if (buffer.length < this.HEADER_SIZE) throw new Error("Packet too small: " + buffer.length + " bytes");

        const version = buffer.readUInt8(0);
        const type = buffer.readUInt8(1);
        const flags = buffer.readUInt16BE(2);
        const uriBuf = buffer.slice(4, 259); // 255 bytes
        const uri = uriBuf.toString('utf8').replace(/\0.*$/, '');
        const length = buffer.readUInt16BE(259);
        const reqId = buffer.readUInt16BE(261);
        const seqNo = buffer.readUInt16BE(263);
        const payload = buffer.slice(this.HEADER_SIZE, this.HEADER_SIZE + length);

        console.log(`Parsed packet, size: ${buffer.length}, type=${type}, flags=${flags}, reqId=${reqId}, length=${length}`);

        return { version, type, flags, uri, length, reqId, seqNo, payload };
    }

    parseFileInfo(buffer: Buffer) {
        console.log('Parsing file info packet of size:', buffer.length);
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

            setTimeout(() => {
                if (this.pendingMulti.has(reqId)) {
                    this.pendingMulti.delete(reqId);
                    reject(new Error('UDP readFile timeout'));
                }
            }, 5000);
        });
    }

    private sendRequestReadDir(uri: vscode.Uri): Promise<MultiReqData[]> {
        const buffer = Buffer.alloc(this.HEADER_SIZE); // Allocate exact size

        const reqId = this.getReqId();

        console.log('sendRequestReadDir reqId=', reqId);

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

            setTimeout(() => {
                if (this.pendingMulti.has(reqId)) {
                    this.pendingMulti.delete(reqId);
                    reject(new Error('UDP readFile timeout'));
                }
            }, 5000);
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
                reject(new Error('UDP request timed out'));
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

}
