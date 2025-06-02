#include <iostream>
#include <iomanip>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <map>
#include <sstream>
#include <algorithm>
#include <openssl/sha.h> // SHA256
#include <openssl/evp.h>

#include "types.hpp" // Include the types header for packet_hdr and enums
#include "AESCipher.hpp"
#include "config.hpp"

namespace fs = std::filesystem;

static uint8_t iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
static uint8_t key[32];

static std::map<std::string, std::vector<SessionData>> writeData;

static void reply_error(int sockfd, const struct sockaddr_in &cliaddr, socklen_t len, uint8_t type, const char *msg, AESCipher &cipher);
static int crypto_sendto(int sockfd, const uint8_t *buf, size_t len, int flags,
                         const struct sockaddr *dest_addr, socklen_t addrlen, AESCipher &cipher);
static std::string hex_dump(const void *data, size_t size);

// Convert file time to ISO 8601 string (UTC)
std::string file_time_to_iso(const fs::file_time_type &ftime)
{
    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
    std::time_t tt = std::chrono::system_clock::to_time_t(sctp);
    std::tm utc_tm = *std::gmtime(&tt);

    std::ostringstream ss;
    ss << std::put_time(&utc_tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

// Platform-specific creation time (Windows and POSIX)
std::string get_creation_time(const std::string &path)
{
    struct stat statbuf;
    if (stat(path.c_str(), &statbuf) != 0)
        return "0";

#if defined(__APPLE__)
    std::time_t ctime = statbuf.st_birthtime;
#else
    std::time_t ctime = statbuf.st_ctime; // May not be creation time
#endif
    std::tm utc_tm = *std::gmtime(&ctime);

    std::ostringstream ss;
    ss << std::put_time(&utc_tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

std::vector<FileEntry> listDirectory(const std::string &path)
{
    std::vector<FileEntry> entries;

    try
    {
        for (const auto &entry : fs::directory_iterator(path))
        {
            FileEntry e;
            e.name = entry.path().filename().string(); // Name only, no full path
            if (entry.is_regular_file())
            {
                e.type = 1;
            }
            else if (entry.is_directory())
            {
                e.type = 2;
            }
            else
            {
                continue; // Skip other types (symlinks, etc.)
            }
            entries.push_back(e);
        }
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Error reading directory: " << ex.what() << std::endl;
    }

    return entries;
}

int main()
{
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    uint8_t recv_buffer[1024];
    // const char *uri_prefix = "udpfs://"; // Prefix for file URIs

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        std::cerr << "Socket creation failed" << std::endl;
        return -1;
    }

    std::string password = "default key";

    auto config = parseConfigFile("config.txt");

    const std::string lookupKey = "key";
    if (config.find(lookupKey) != config.end())
    {
        password = config[lookupKey];
        std::cout << "key was found\n";
    }
    else
    {
        std::cerr << "Key not found: \n";
    }

    // Hash the password using SHA256
    SHA256(reinterpret_cast<const unsigned char *>(password.data()), password.size(), key);

    // std::cout << "key: " << hex_dump(key, 32) << "\niv: " << hex_dump(iv, 16) << "\n";
    AESCipher cipher(key, iv);

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Bind to any address
    server_addr.sin_port = htons(9022);       // Port number

    // Bind the socket to the address and port
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        std::cerr << "Bind failed" << std::endl;
        close(sockfd);
        return -1;
    }

    std::cout << "Server is running on port " << ntohs(server_addr.sin_port) << std::endl;
    std::cout << "Waiting for packets..." << std::endl;

    uint8_t send_buffer[1024];
    ssize_t sent_bytes = 0;
    packet_hdr *send_hdr = reinterpret_cast<packet_hdr *>(send_buffer);

    while (true)
    {
        // Receive data from client
        ssize_t len = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer) - 1, 0,
                               (struct sockaddr *)&client_addr, &addr_len);
        if (len < 0)
        {
            std::cerr << "Receive failed" << std::endl;
            break;
        }

        try
        {
            std::vector<uint8_t> decrypted = cipher.decrypt(recv_buffer, len);
            memcpy(recv_buffer, decrypted.data(), decrypted.size());
        }
        catch (std::runtime_error ex)
        {
            std::cerr << "Decryption failed\n";
            continue;
        }

        char ip_str[INET_ADDRSTRLEN]; // Buffer to hold the IP address string

        struct sockaddr_in *ipv4_addr = (struct sockaddr_in *)&client_addr;

        // Convert the binary IP address to a human-readable string
        inet_ntop(AF_INET, &(ipv4_addr->sin_addr), ip_str, INET_ADDRSTRLEN);

        // Convert the network byte order port to host byte order
        int port = ntohs(ipv4_addr->sin_port);

        std::string client_id = std::string(ip_str) + ":" + std::to_string(port);

        packet_hdr *hdr = reinterpret_cast<packet_hdr *>(recv_buffer);
        hdr->flags = ntohs(hdr->flags);
        hdr->length = ntohs(hdr->length);
        hdr->seqNo = ntohs(hdr->seqNo);

        std::cout << "# Received packet: "
                  << "Version: " << static_cast<int>(hdr->version) << ", "
                  << "Type: " << static_cast<int>(hdr->type) << ", "
                  << "Flags: " << hdr->flags << ", "
                  << "URI: " << hdr->uri << ", "
                  << "Length: " << hdr->length << std::endl;

        if (hdr->length > len - sizeof(packet_hdr))
        {
            std::cerr << "Packet length " << hdr->length << " received more than data size" << std::endl;
            reply_error(sockfd, client_addr, addr_len, hdr->type, "Packet length exceeds received data size", cipher);
            continue; // Skip processing this packet
        }

        const char *file_path = reinterpret_cast<const char *>(hdr->uri); // + strlen(uri_prefix); // Remove the prefix
        send_hdr->reqId = hdr->reqId;                                     // NOTE: none converted to host
        send_hdr->version = hdr->version;
        send_hdr->type = hdr->type;
        send_hdr->seqNo = htons(hdr->seqNo);

        // Process the packet based on its type
        if (hdr->type == READ_FILE)
        {
            std::cout << "Processing READ_FILE request for URI: " << hdr->uri << std::endl;

            // Open the file in binary mode
            std::ifstream file(file_path, std::ios::binary);
            if (!file)
            {
                std::cerr << "Error: Could not open file " << file_path << std::endl;
                reply_error(sockfd, client_addr, addr_len, hdr->type, std::string(std::string("File not found: ") + file_path).c_str(), cipher);
                continue; // Skip processing this packet
            }

            // Read the file into a buffer
            std::vector<char> buffer((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());

            file.close();
            send_hdr->flags = 0;

            // Send the file content back to the client
            size_t file_size = buffer.size();
            size_t offset = 0;
            uint16_t seqNo = 0;
            while (file_size >= 0)
            {
                size_t chunk_size = std::min(file_size, static_cast<size_t>(sizeof(send_buffer) - sizeof(packet_hdr)));
                send_hdr->length = htons(static_cast<uint16_t>(chunk_size));
                send_hdr->seqNo = htons(seqNo++);
                if (file_size <= (sizeof(send_buffer) - sizeof(packet_hdr)))
                {
                    send_hdr->flags = htons(PacketFlags::LAST_DATA); // Set LAST_DATA flag for the last chunk
                }

                memcpy(send_buffer + sizeof(packet_hdr), buffer.data() + offset, chunk_size);
                send_hdr->uri[0] = '\0'; // Clear the URI in the response`
                sent_bytes = crypto_sendto(sockfd, send_buffer,
                                           sizeof(packet_hdr) + chunk_size, 0,
                                           (struct sockaddr *)&client_addr, addr_len, cipher);
                if (sent_bytes < 0)
                {
                    std::cerr << "Error sending file data" << std::endl;
                    break; // Exit on send error
                }
                file_size -= chunk_size;
                offset += chunk_size;
                std::cout << "File " << file_path << " sent successfully, sent " << (sizeof(packet_hdr) + chunk_size) << " bytes." << std::endl;

                if (file_size == 0)
                    break;
            }
        }
        else if (hdr->type == WRITE_FILE)
        {
            std::cout << "Processing WRITE_FILE request for URI: " << hdr->uri << ", seqNo: " << hdr->seqNo << std::endl;

            SessionData data;
            memcpy(data.buffer, recv_buffer + sizeof(packet_hdr), hdr->length);
            data.length = hdr->length;
            data.seqNo = hdr->seqNo;
            writeData[file_path].push_back(data);

            if (hdr->flags & PacketFlags::LAST_DATA)
            {
                // write file
                std::vector<SessionData> &packets = writeData[file_path];

                // Sort in ascending order by seqNo
                std::sort(packets.begin(), packets.end(), [](const SessionData &a, const SessionData &b)
                          { return a.seqNo < b.seqNo; });

                uint16_t seq = 0;
                bool ok = true;
                for (const SessionData &packet : packets)
                {
                    if (packet.seqNo != seq)
                    {
                        std::cerr << "Seq No mismatch: " << file_path << ", " << packet.seqNo << " != " << seq << std::endl;
                        reply_error(sockfd, client_addr, addr_len, hdr->type, "Can't write file", cipher);
                        ok = false;
                        break;
                    }
                }

                if (!ok)
                {
                    continue;
                }

                // open file for write and append, or create file
                std::ofstream outFile;
                outFile.open(file_path, std::ios::binary | std::ios::trunc);
                if (!outFile)
                {
                    std::cerr << "Failed to open file for writing: " << file_path << std::endl;
                    reply_error(sockfd, client_addr, addr_len, hdr->type, "Can't open file for writing", cipher);
                    continue;
                }

                seq = 0;
                for (const SessionData &packet : packets)
                {
                    if (packet.seqNo != seq)
                    {
                        std::cerr << "Seq No mismatch: " << file_path << ", " << packet.seqNo << " != " << seq << std::endl;
                        reply_error(sockfd, client_addr, addr_len, hdr->type, "Can't write file", cipher);
                        break;
                    }

                    ++seq;

                    outFile.write(reinterpret_cast<const char *>(packet.buffer), packet.length);
                }

                outFile.close();

                writeData.erase(file_path);

                // reply for ACK
                send_hdr->flags = 0;
                send_hdr->length = 0;
                sent_bytes = crypto_sendto(sockfd, send_buffer,
                                           sizeof(packet_hdr), 0,
                                           (struct sockaddr *)&client_addr, addr_len, cipher);
            }
        }
        else if (hdr->type == DELETE_FILE)
        {
            std::cout << "Processing DELETE_FILE request for URI: " << hdr->uri << std::endl;

            try
            {
                if (!fs::exists(file_path))
                {
                    std::cerr << "Path does not exist.\n";
                    reply_error(sockfd, client_addr, addr_len, hdr->type, "Path does not exist", cipher);
                    continue; // Skip processing this packet
                }

                if (fs::is_regular_file(file_path))
                {
                    if (std::filesystem::remove(file_path))
                    {
                        std::cout << "File " << file_path << " deleted successfully.\n";
                    }
                    else
                    {
                        std::cout << "Failed to delete the file: " << file_path << "\n";
                        reply_error(sockfd, client_addr, addr_len, hdr->type, "Can't delete file", cipher);
                        continue;
                    }
                }
                else if (fs::is_directory(file_path))
                {
                    if (std::filesystem::remove_all(file_path))
                    {
                        std::cout << "Directory " << file_path << " deleted successfully.\n";
                    }
                    else
                    {
                        std::cout << "Failed to delete the directory: " << file_path << "\n";
                        reply_error(sockfd, client_addr, addr_len, hdr->type, "Can't delete directory", cipher);
                        continue;
                    }
                }
            }
            catch (const std::filesystem::filesystem_error &e)
            {
                std::cerr << "Filesystem error: " << e.what() << '\n';
                reply_error(sockfd, client_addr, addr_len, hdr->type, "Error during deleting", cipher);
                continue;
            }

            send_hdr->flags = 0;
            send_hdr->length = 0;

            crypto_sendto(sockfd, send_buffer, sizeof(packet_hdr) + sizeof(file_info), 0,
                          (const struct sockaddr *)&client_addr, addr_len, cipher);
        }
        else if (hdr->type == LIST_FILES)
        {
            std::cout << "Processing LIST_FILES request" << std::endl;
            auto files = listDirectory(file_path);

            send_hdr->flags = 0;

            // packet files in format: items num (byte), file type (byte), name length (byte), name bytes

            size_t count = 0; // inside one packet
            size_t added = 0; // total
            uint16_t seqNo = 0;
            size_t maxSize = sizeof(send_buffer) - sizeof(packet_hdr);
            size_t packed = 1; // first byte is num of entries
            uint8_t *p = send_buffer + sizeof(packet_hdr) + 1;
            for (const auto &f : files)
            {
                // std::cout << "File: " << f.name << ", type: " << f.type << "\n";
                if ((packed + f.name.length() + 2) > maxSize)
                {
                    // cannot pack next - send packet
                    p = send_buffer + sizeof(packet_hdr);
                    *p = count;
                    ++p;
                    send_hdr->length = htons(packed + 1);
                    send_hdr->seqNo = htons(seqNo++);
                    if (added == files.size())
                    {
                        send_hdr->flags = htons(PacketFlags::LAST_DATA);
                    }
                    crypto_sendto(sockfd, send_buffer, sizeof(packet_hdr) + packed, 0,
                                  (const struct sockaddr *)&client_addr, addr_len, cipher);

                    count = 0;
                    packed = 1;
                }
                *p = f.type;
                ++p;
                *p = f.name.length();
                ++p;
                memcpy(p, f.name.c_str(), f.name.length());
                p += f.name.length();
                packed += (2 + f.name.length());

                ++count;
                ++added;
            }

            if (count > 0)
            {
                // send rest

                // set count:
                p = send_buffer + sizeof(packet_hdr);
                *p = count;

                send_hdr->length = htons(packed + 1);
                send_hdr->flags = htons(PacketFlags::LAST_DATA);
                send_hdr->seqNo = htons(seqNo++);
                crypto_sendto(sockfd, send_buffer, sizeof(packet_hdr) + packed, 0,
                              (const struct sockaddr *)&client_addr, addr_len, cipher);
                std::cout << "Sent last: total=" << added << ", packed=" << packed << ", flags=" << ntohs(send_hdr->flags) << "\n";
            }
        }
        else if (hdr->type == FILE_INFO)
        {
            std::cout << "Processing FILE_INFO request for URI: " << hdr->uri << std::endl;
            fs::path fpath(file_path);

            if (!fs::exists(file_path))
            {
                std::cerr << "Path does not exist.\n";
                reply_error(sockfd, client_addr, addr_len, hdr->type, "Path does not exist", cipher);
                continue; // Skip processing this packet
            }

            file_info *info = reinterpret_cast<file_info *>(send_buffer + sizeof(packet_hdr));

            std::string type;
            if (fs::is_regular_file(file_path))
                info->type = 1; // file
            else if (fs::is_directory(file_path))
                info->type = 2; // directory
            else if (fs::is_symlink(file_path))
                info->type = 64; // symlink
            else
                info->type = 0; // unknown

            auto size = fs::is_regular_file(file_path) ? fs::file_size(file_path) : 0;
            auto mtime = fs::last_write_time(file_path);
            std::string modify_time = file_time_to_iso(mtime);
            std::string creation_time = get_creation_time(file_path);
            info->size = htonl(static_cast<uint32_t>(size));
            strncpy(info->ctime, creation_time.c_str(), sizeof(info->ctime) - 1);
            info->ctime[sizeof(info->ctime) - 1] = '\0'; // Ensure null-termination
            strncpy(info->mtime, modify_time.c_str(), sizeof(info->mtime) - 1);
            info->mtime[sizeof(info->mtime) - 1] = '\0'; // Ensure null-termination

            send_hdr->flags = 0; // No flags for file info
            send_hdr->length = htons((short)sizeof(file_info));

            std::cout << "File info for " << file_path << ": "
                      << "Size: " << size << ", "
                      << "Type: " << static_cast<int>(info->type) << ", "
                      << "Creation Time: " << info->ctime << ", "
                      << "Modification Time: " << info->mtime << std::endl;

            sent_bytes = crypto_sendto(sockfd, send_buffer, sizeof(packet_hdr) + sizeof(file_info), 0,
                                       (const struct sockaddr *)&client_addr, addr_len, cipher);
            if (sent_bytes < 0)
            {
                std::cerr << "Error sending file info" << std::endl;
                continue; // Exit on send error
            }
            std::cout << "File info sent successfully for " << file_path << " sent " << sent_bytes << " bytes." << std::endl;
            std::cout << "Sent " << sizeof(packet_hdr) + sizeof(file_info) << " bytes in response." << std::endl;
        }
        else if (hdr->type == PacketType::CREATE_DIRECTORY)
        {
            if (fs::create_directory(file_path))
            {
                std::cout << "Directory created: " << file_path << '\n';
                send_hdr->flags = 0;
                send_hdr->length = 0;
                sent_bytes = crypto_sendto(sockfd, send_buffer,
                                           sizeof(packet_hdr), 0,
                                           (struct sockaddr *)&client_addr, addr_len, cipher);
            }
            else
            {
                std::cerr << "Can't create directory: " << file_path << '\n';
                reply_error(sockfd, client_addr, addr_len, hdr->type, "Can't create directory", cipher);
            }
        }
        else if (hdr->type == PacketType::RENAME_FILE)
        {
            char newName[255] = {0};
            try
            {

                memcpy(newName, recv_buffer + sizeof(packet_hdr), hdr->length);
                if (!fs::exists(file_path))
                {
                    std::cerr << "Path does not exist.\n";
                    reply_error(sockfd, client_addr, addr_len, hdr->type, "Path does not exist", cipher);
                    continue; // Skip processing this packet
                }

                std::filesystem::rename(file_path, newName);
            }
            catch (const std::filesystem::filesystem_error &e)
            {
                std::cerr << "Filesystem error on rename from " << file_path << " to " << newName << ": " << e.what() << '\n';
                reply_error(sockfd, client_addr, addr_len, hdr->type, "Error during renaming", cipher);
                continue;
            }

            send_hdr->flags = 0;
            send_hdr->length = 0;

            crypto_sendto(sockfd, send_buffer, sizeof(packet_hdr) + sizeof(file_info), 0,
                          (const struct sockaddr *)&client_addr, addr_len, cipher);
        }
        else
        {
            std::cerr << "Unknown packet type received" << std::endl;
        }
    }

    close(sockfd);
    return 0;
}

static void reply_error(int sockfd, const struct sockaddr_in &cliaddr, socklen_t len, uint8_t type, const char *msg, AESCipher &cipher)
{
    uint8_t reply[1024];
    struct packet_hdr *hdr = reinterpret_cast<struct packet_hdr *>(reply);
    hdr->version = 1;
    hdr->type = type;
    hdr->flags = htons(PacketFlags::ERROR);
    hdr->length = htons(strlen(msg) + 1);
    memcpy(reply + sizeof(struct packet_hdr), msg, strlen(msg) + 1);
    crypto_sendto(sockfd, reply, sizeof(struct packet_hdr) + strlen(msg) + 1, 0, (const struct sockaddr *)&cliaddr, len, cipher);
}

static int crypto_sendto(int sockfd, const uint8_t *buf, size_t len, int flags,
                         const struct sockaddr *dest_addr, socklen_t addrlen, AESCipher &cipher)
{
    std::vector<uint8_t> encrypted_data = cipher.encrypt(buf, len);
    return sendto(sockfd, encrypted_data.data(), encrypted_data.size(), flags, dest_addr, addrlen);
}

static std::string hex_dump(const void *data, size_t size)
{
    std::stringstream ss;
    const uint8_t *bytes = static_cast<const uint8_t *>(data);

    for (size_t i = 0; i < size; ++i)
    {
        ss << /*std::hex << std::setw(2) << std::setfill('0') << */ static_cast<int>(bytes[i]) << " ";
    }

    return ss.str();
}
