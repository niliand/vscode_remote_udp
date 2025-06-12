#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <map>
#include <regex>
#include <sstream>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <unordered_set>
#include <vector>

#include <fcntl.h> // open
#include <memory.h>
#include <string.h> // strstr, memchr
#include <unistd.h> // read, close

#include <openssl/evp.h>
#include <openssl/sha.h> // SHA256

#include "AESCipher.hpp"
#include "config.hpp"
#include "types.hpp" // Include the types header for packet_hdr and enums

namespace fs = std::filesystem;
using namespace std::chrono_literals; // Enables 1s, 500ms, etc. literals

static uint8_t iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
static uint8_t key[32];

static std::map<std::string, SessionDataValue> writeData;

static void reply_error(int sockfd, const struct sockaddr_in &cliaddr, socklen_t len, uint8_t type,
                        const char *msg, AESCipher &cipher);
static int crypto_sendto(int sockfd, const uint8_t *buf, size_t len, int flags,
                         const struct sockaddr *dest_addr, socklen_t addrlen, AESCipher &cipher);
// static std::string hex_dump(const void *data, size_t size);
void writeDataCleaupTask(std::string path, std::weak_ptr<bool> token_weak_ptr) {
    // wait
    std::this_thread::sleep_for(std::chrono::seconds(60));

    if (token_weak_ptr.lock()) {
        // cleaup
        // std::cout << "writeDataCleaupTask: erase " << path << "\n";
        writeData.erase(path);
    }
}

std::pair<std::string, std::string> splitPathAndMask(const std::string &input) {
    size_t pos = input.find_last_of("/\\");
    if (pos == std::string::npos) {
        // No slash found, treat whole input as mask
        return {"", input};
    } else {
        return {input.substr(0, pos + 1), input.substr(pos + 1)};
    }
}

// Helper to convert a wildcard pattern (like *.txt) into a regex
std::regex wildcard_to_regex(const std::string &pattern) {
    std::string regex_pattern;
    for (char c : pattern) {
        switch (c) {
        case '*':
            regex_pattern += ".*";
            break;
        case '?':
            regex_pattern += ".";
            break;
        case '.':
            regex_pattern += "\\.";
            break;
        default:
            regex_pattern += c;
            break;
        }
    }
    return std::regex(regex_pattern, std::regex::icase);
}

std::string to_lower(const std::string &s) {
    std::string lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return lower;
}

void fast_search_in_file(const fs::path &file_path, const char *search_text, bool case_sensitive,
                         bool whole_word, bool regex, std::vector<SearchResult> &results) {

    const size_t BUFFER_SIZE = 1 << 20; // 1 MB buffer

    int fd = open(file_path.c_str(), O_RDONLY);
    if (fd < 0) {
        perror("open");
        std::cerr << "Error: Could not open file '" << file_path << "'" << std::endl;
        return;
    }

    std::regex compiled_regex;
    bool use_regex = false;
    uint16_t line_number = 1;

    try {
        if (regex) {
            compiled_regex = case_sensitive ? std::regex(search_text)
                                            : std::regex(search_text, std::regex_constants::icase);
            use_regex = true;
        } else if (whole_word) {
            std::string pattern = std::string("\\b") + std::string(search_text) + "\\b";
            compiled_regex = case_sensitive ? std::regex(pattern)
                                            : std::regex(pattern, std::regex_constants::icase);
            use_regex = true;
        }
    } catch (const std::regex_error &e) {
        std::cerr << "Invalid regex pattern: " << search_text << " (" << e.what() << ")\n";
        results.push_back(
            {file_path,
             std::string("Invalid regex pattern: ") + search_text + " (" + e.what() + ")", 0});
        return;
    }

    char *buffer = new char[BUFFER_SIZE + 1]; // +1 for null-terminator
    size_t leftover_size = 0;
    char *leftover = new char[BUFFER_SIZE];

    ssize_t bytes_read;
    bool match = false;
    while ((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0) {
        buffer[bytes_read] = '\0'; // Null-terminate
        size_t total_size = leftover_size + bytes_read;

        // Create a complete buffer with leftover from last read
        char *chunk = new char[total_size + 1];
        memcpy(chunk, leftover, leftover_size);
        memcpy(chunk + leftover_size, buffer, bytes_read);
        chunk[total_size] = '\0';

        // Line by line scan
        char *start = chunk;
        while (true) {
            match = false;

            char *newline = (char *)memchr(start, '\n', chunk + total_size - start);
            if (!newline)
                break;

            *newline = '\0'; // Temporarily terminate the line

            if (use_regex) {
                match = std::regex_search(start, compiled_regex);
            } else {
                if (case_sensitive) {
                    if (strstr(start, search_text)) {
                        match = true;
                    }
                } else {
                    if (strcasestr(start, search_text)) {
                        match = true;
                    }
                }
            }
            if (match) {
                std::string line(start);
                std::string snippet = line.length() > 250 ? line.substr(0, 250) : line;
                results.push_back({file_path, snippet, line_number});
                // std::cout << "found text: " << file_path << ":" << line_number << ":
                // " << snippet << "\n";
            }

            start = newline + 1;

            ++line_number;
            if (line_number == 0xFFFF) {
                break; // max line number is 65535 for now
            }
        }

        // Save leftover bytes for next round
        leftover_size = chunk + total_size - start;
        if (leftover_size > BUFFER_SIZE) {
            // too long line
            delete[] chunk;
            break;
        }
        memcpy(leftover, start, leftover_size);

        delete[] chunk;

        if (line_number == 0xFFFF) {
            break; // max line number is 65535 for now
        }
    }

    // Handle final leftover (if no newline at end)
    if (leftover_size > 0) {
        match = false;
        leftover[leftover_size] = '\0';

        if (use_regex) {
            match = std::regex_search(leftover, compiled_regex);
        } else {
            if (case_sensitive) {
                if (strstr(leftover, search_text)) {
                    match = true;
                }
            } else {
                if (strcasestr(leftover, search_text)) {
                    match = true;
                }
            }
        }
        if (match) {
            std::string line(leftover);
            std::string snippet = line.length() > 250 ? line.substr(0, 250) : line;
            results.push_back({file_path, snippet, line_number});
            // std::cout << "found text: " << file_path << ":" << line_number << ": "
            // << snippet << "\n";
        }
    }

    delete[] buffer;
    delete[] leftover;
    close(fd);
}

void search_in_file(const fs::path &file_path, const std::string &search_text, bool case_sensitive,
                    bool whole_word, bool regex, std::vector<SearchResult> &results) {
    std::ifstream file(file_path);
    if (!file.is_open())
        return;

    std::string line;
    uint16_t line_number = 0;

    std::regex compiled_regex;
    bool use_regex = false;

    try {
        if (regex) {
            compiled_regex = case_sensitive ? std::regex(search_text)
                                            : std::regex(search_text, std::regex_constants::icase);
            use_regex = true;
        } else if (whole_word) {
            std::string pattern = "\\b" + search_text + "\\b";
            compiled_regex = case_sensitive ? std::regex(pattern)
                                            : std::regex(pattern, std::regex_constants::icase);
            use_regex = true;
        }
    } catch (const std::regex_error &e) {
        std::cerr << "Invalid regex pattern: " << search_text << " (" << e.what() << ")\n";
        results.push_back(
            {file_path,
             std::string("Invalid regex pattern: ") + search_text + " (" + e.what() + ")", 0});
        return;
    }

    while (std::getline(file, line)) {
        ++line_number;
        bool match = false;

        if (use_regex) {
            match = std::regex_search(line, compiled_regex);
        } else {
            std::string haystack = case_sensitive ? line : to_lower(line);
            std::string needle = case_sensitive ? search_text : to_lower(search_text);
            match = haystack.find(needle) != std::string::npos;
        }

        if (match) {
            std::string snippet = line.length() > 250 ? line.substr(0, 250) : line;
            results.push_back({file_path, snippet, line_number});
            std::cout << "found text: " << file_path << ":" << line_number << ": " << snippet
                      << "\n";
        }

        if (line_number == 0xFFFF) {
            break; // max line number is 65535 for now
        }
    }
}

std::string regex_escape(const std::string &s) {
    static const std::regex re{R"([-[\]{}()*+?.,\^$|#\s])"};
    return std::regex_replace(s, re, R"(\$&)");
}

std::regex globToRegex(const std::string &glob) {
    std::string regex = "^";
    for (size_t i = 0; i < glob.size(); ++i) {
        char c = glob[i];
        if (c == '*') {
            if (i + 1 < glob.size() && glob[i + 1] == '*') {
                regex += ".*";
                ++i;
            } else {
                regex += "[^/]*";
            }
        } else if (c == '?') {
            regex += '.';
        } else if (c == '.') {
            regex += "\\.";
        } else {
            regex += regex_escape(std::string(1, c));
        }
    }
    regex += "$";
    return std::regex(regex);
}

bool isExcluded(const fs::path &path, const std::vector<std::regex> &excludes) {
    std::string strPath = path.generic_string();
    for (const auto &re : excludes) {
        if (std::regex_match(strPath, re)) {
            return true;
        }
    }
    return false;
}

void search_files(const std::string &root_dir, const std::string &file_mask,
                  const std::string &search_text, const std::vector<std::regex> &excludes,
                  bool case_sens, bool whole_word, bool regex, std::vector<SearchResult> &results) {
    std::regex file_regex = wildcard_to_regex(file_mask);

    try {
        for (auto it = fs::recursive_directory_iterator(root_dir);
             it != fs::recursive_directory_iterator(); ++it) {
            const auto &entry = *it;
            const auto &path = entry.path();

            if (isExcluded(path, excludes)) {
                std::cout << "Skip search in " << entry.path().filename().string() << "\n";
                if (fs::is_directory(path)) {
                    it.disable_recursion_pending(); // Don't descend into it
                }
                continue; // Skip this file/dir
            }
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();

                if (std::regex_match(filename, file_regex)) {
                    if (search_text.length() > 0) {
                        fast_search_in_file(entry.path(), search_text.c_str(), case_sens,
                                            whole_word, regex, results);
                    } else {
                        // just search files
                        results.push_back({entry.path(), "", 0});
                        // std::cout << "found file: " << entry.path() << "\n";
                    }
                }
            }
        }
    } catch (const fs::filesystem_error &ex) {
        std::cerr << "Filesystem Error during search:\n";
        std::cerr << "  What: " << ex.what() << '\n';
        std::cerr << "  Code value: " << ex.code().value() << '\n';
        std::cerr << "  Code message: " << ex.code().message() << '\n';
    }
}

void search_for_file(const std::string &root_dir, const std::string &file_mask,
                     const std::vector<std::regex> &excludes, std::vector<SearchResult> &results) {

    try {
        for (auto it = fs::recursive_directory_iterator(root_dir);
             it != fs::recursive_directory_iterator(); ++it) {
            const auto &entry = *it;
            const auto &path = entry.path();

            if (isExcluded(path, excludes)) {
                std::cout << "Skip search in " << entry.path().filename().string() << "\n";
                if (fs::is_directory(path)) {
                    it.disable_recursion_pending(); // Don't descend into it
                }
                continue; // Skip this file/dir
            }
            if (entry.is_regular_file()) {
                std::string rel_path = fs::relative(entry.path(), root_dir).generic_string();

                if (rel_path.find(file_mask) != std::string::npos) {
                    if (std::none_of(results.begin(), results.end(),
                                     [path](const SearchResult &p) { return p.path == path; })) {
                        results.push_back({path, "", 0});
                    }
                    // std::cout << "found file: " << entry.path() << "\n";
                }
            }
        }
    } catch (const fs::filesystem_error &ex) {
        std::cerr << "Filesystem Error during search:\n";
        std::cerr << "  What: " << ex.what() << '\n';
        std::cerr << "  Code value: " << ex.code().value() << '\n';
        std::cerr << "  Code message: " << ex.code().message() << '\n';
    }
}

std::vector<std::string> fast_grep_tags(const std::string &filename, const std::string &pattern) {
    std::vector<std::string> matching_lines;
    size_t pattern_len = pattern.length();
    const size_t BUFFER_SIZE = 1 << 20; // 1 MB buffer

    int fd = open(filename.c_str(), O_RDONLY);
    if (fd < 0) {
        perror("open");
        std::cerr << "Error: Could not open file '" << filename << "'" << std::endl;
        return matching_lines; // Return empty vector on error
    }

    char *buffer = new char[BUFFER_SIZE + 1]; // +1 for null-terminator
    size_t leftover_size = 0;
    char *leftover = new char[BUFFER_SIZE];

    ssize_t bytes_read;
    while ((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0) {
        buffer[bytes_read] = '\0'; // Null-terminate
        size_t total_size = leftover_size + bytes_read;

        // Create a complete buffer with leftover from last read
        char *chunk = new char[total_size + 1];
        memcpy(chunk, leftover, leftover_size);
        memcpy(chunk + leftover_size, buffer, bytes_read);
        chunk[total_size] = '\0';

        // Line by line scan
        char *start = chunk;
        while (true) {
            char *newline = (char *)memchr(start, '\n', chunk + total_size - start);
            if (!newline)
                break;

            *newline = '\0'; // Temporarily terminate the line
            if (strstr((const char *)start, pattern.c_str()) && start[pattern_len] == '\t') {
                matching_lines.push_back(start);
            }

            start = newline + 1;
        }

        // Save leftover bytes for next round
        leftover_size = chunk + total_size - start;
        if (leftover_size > BUFFER_SIZE) {
            // too long line
            delete[] chunk;
            break;
        }
        memcpy(leftover, start, leftover_size);

        delete[] chunk;
    }

    // Handle final leftover (if no newline at end)
    if (leftover_size > 0) {
        leftover[leftover_size] = '\0';
        if (strstr((const char *)leftover, pattern.c_str()) && leftover[pattern_len] == '\t') {
            matching_lines.push_back(leftover);
        }
    }

    delete[] buffer;
    delete[] leftover;
    close(fd);
    return matching_lines;
}

std::vector<std::string> grep_tags(const std::string &filename, const std::string &pattern) {
    std::vector<std::string> matching_lines;
    std::ifstream file(filename);

    // Check if the file was opened successfully
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file '" << filename << "'" << std::endl;
        return matching_lines; // Return empty vector on error
    }

    size_t pattern_end_index = pattern.length();

    std::string line;
    // Read the file line by line
    while (std::getline(file, line)) {
        // 1. Check if the line starts with the exact pattern
        // `rfind(pattern, 0)` is an efficient way to check if a string starts with
        // a substring.
        if (line.rfind(pattern, 0) == 0) {
            // The pattern is found at the beginning of the line.

            if (pattern_end_index < line.length()) {
                char char_after_pattern = line[pattern_end_index];

                if (char_after_pattern == '\t') {
                    matching_lines.push_back(line);
                }
            }
        }
    }

    file.close(); // Close the file stream
    return matching_lines;
}

// Convert file time to ISO 8601 string (UTC)
std::string file_time_to_iso(const fs::file_time_type &ftime) {
    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
    std::time_t tt = std::chrono::system_clock::to_time_t(sctp);
    std::tm utc_tm = *std::gmtime(&tt);

    std::ostringstream ss;
    ss << std::put_time(&utc_tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

// Platform-specific creation time (Windows and POSIX)
std::string get_creation_time(const std::string &path) {
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

std::vector<FileEntry> listDirectory(const std::string &path) {
    std::vector<FileEntry> entries;

    try {
        for (const auto &entry : fs::directory_iterator(path)) {
            FileEntry e;
            e.name = entry.path().filename().string(); // Name only, no full path
            if (entry.is_regular_file()) {
                e.type = 1;
            } else if (entry.is_directory()) {
                e.type = 2;
            } else {
                continue; // Skip other types (symlinks, etc.)
            }
            entries.push_back(e);
        }
    } catch (const std::exception &ex) {
        std::cerr << "Error reading directory: " << ex.what() << std::endl;
    }

    return entries;
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    uint8_t recv_buffer[1024];
    // const char *uri_prefix = "udpfs://"; // Prefix for file URIs

    std::srand(static_cast<unsigned int>(std::time(NULL)));

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        std::cerr << "Socket creation failed" << std::endl;
        return -1;
    }

    std::string password = "default key";

    auto config = parseConfigFile("config.txt");

    const std::string lookupKey = "key";
    if (config.find(lookupKey) != config.end()) {
        password = config[lookupKey];
        std::cout << "key was found\n";
    } else {
        std::cerr << "Key not found: \n";
    }

    // Hash the password using SHA256
    SHA256(reinterpret_cast<const unsigned char *>(password.data()), password.size(), key);

    // std::cout << "key: " << hex_dump(key, 32) << "\niv: " << hex_dump(iv, 16)
    // << "\n";
    AESCipher cipher(key, iv);

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Bind to any address
    server_addr.sin_port = htons(9022);       // Port number

    // Bind the socket to the address and port
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Bind failed" << std::endl;
        close(sockfd);
        return -1;
    }

    std::cout << "Server is running on port " << ntohs(server_addr.sin_port) << std::endl;
    std::cout << "Waiting for packets..." << std::endl;

    uint8_t send_buffer[MAX_PACKET_SIZE];
    ssize_t sent_bytes = 0;
    packet_hdr *send_hdr = reinterpret_cast<packet_hdr *>(send_buffer);

    while (true) {
        // Receive data from client
        ssize_t len = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer) - 1, 0,
                               (struct sockaddr *)&client_addr, &addr_len);
        if (len < 0) {
            std::cerr << "Receive failed" << std::endl;
            break;
        }

        try {
            std::vector<uint8_t> decrypted = cipher.decrypt(recv_buffer, len);
            memcpy(recv_buffer, decrypted.data(), decrypted.size());
        } catch (std::runtime_error ex) {
            std::cerr << "Decryption failed\n";
            continue;
        }

        /*
        char ip_str[INET_ADDRSTRLEN]; // Buffer to hold the IP address string

        struct sockaddr_in *ipv4_addr = (struct sockaddr_in *)&client_addr;

        // Convert the binary IP address to a human-readable string
        inet_ntop(AF_INET, &(ipv4_addr->sin_addr), ip_str, INET_ADDRSTRLEN);

        // Convert the network byte order port to host byte order
        int port = ntohs(ipv4_addr->sin_port);

        std::string client_id = std::string(ip_str) + ":" + std::to_string(port);
        */
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

        if (hdr->length > len - sizeof(packet_hdr)) {
            std::cerr << "Packet length " << hdr->length << " received more than data size"
                      << std::endl;
            reply_error(sockfd, client_addr, addr_len, hdr->type,
                        "Packet length exceeds received data size", cipher);
            continue; // Skip processing this packet
        }

        const char *file_path = reinterpret_cast<const char *>(hdr->uri);
        send_hdr->reqId = hdr->reqId; // NOTE: none converted to host
        send_hdr->version = hdr->version;
        send_hdr->type = hdr->type;
        send_hdr->seqNo = htons(hdr->seqNo);
        memcpy(send_hdr->uri, hdr->uri, sizeof(hdr->uri));

        // Process the packet based on its type
        if (hdr->type == PacketType::READ_FILE) {
            std::cout << "Processing READ_FILE request for URI: " << hdr->uri << std::endl;

            // Open the file in binary mode
            std::ifstream file(file_path, std::ios::binary);
            if (!file) {
                std::cerr << "Error: Could not open file " << file_path << std::endl;
                reply_error(sockfd, client_addr, addr_len, hdr->type,
                            std::string(std::string("File not found: ") + file_path).c_str(),
                            cipher);
                continue; // Skip processing this packet
            }

            auto size = fs::is_regular_file(file_path) ? fs::file_size(file_path) : 0;
            if (size > 45000000) {
                std::cerr << "Error: too big file to read: " << size << std::endl;
                reply_error(sockfd, client_addr, addr_len, hdr->type,
                            std::string(std::string("File too big to read: ") + file_path).c_str(),
                            cipher);
                continue; // Skip processing this packet
            }

            std::unordered_set<int> missingSeq;
            bool onlyMissing = false;
            uint16_t lastSeqNo = 0;
            if (hdr->flags & PacketFlags::SEQ_NO) {
                onlyMissing = true;
                size_t count = hdr->length / 2;
                std::cout << "MISS[" << count << "]: ";
                uint16_t *pSeq = reinterpret_cast<uint16_t *>(recv_buffer + sizeof(packet_hdr));
                for (size_t i = 0; i < count; ++i) {
                    uint16_t val = ntohs(pSeq[i]);
                    missingSeq.insert(val);
                    std::cout << val << ", ";
                    if (val > lastSeqNo)
                        lastSeqNo = val;
                }
                std::cout << " lastSeqNo=" << lastSeqNo << "\n";
            }

            // Read the file into a buffer
            std::vector<char> buffer((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());

            file.close();

            packet_hdr saved_send_hdr = *send_hdr;
            std::thread([saved_send_hdr, sockfd, client_addr, addr_len, &cipher, buffer,
                         onlyMissing, missingSeq, lastSeqNo] {
                uint8_t send_buffer[MAX_PACKET_SIZE];
                packet_hdr *send_hdr = reinterpret_cast<packet_hdr *>(send_buffer);
                memcpy(send_hdr, &saved_send_hdr, sizeof(packet_hdr));

                send_hdr->flags = 0;

                // Send the file content back to the client
                size_t file_size = buffer.size();
                size_t offset = 0;
                uint16_t seqNo = 0;
                size_t sent = 0;
                while (file_size >= 0) {
                    size_t chunk_size = std::min(
                        file_size, static_cast<size_t>(sizeof(send_buffer) - sizeof(packet_hdr)));
                    send_hdr->length = htons(static_cast<uint16_t>(chunk_size));
                    send_hdr->seqNo = htons(seqNo);

                    if (file_size <= (sizeof(send_buffer) - sizeof(packet_hdr))) {
                        send_hdr->flags = htons(PacketFlags::LAST_DATA); // Set LAST_DATA flag for
                                                                         // the last chunk
                    }

                    memcpy(send_buffer + sizeof(packet_hdr), buffer.data() + offset, chunk_size);

                    if (!onlyMissing || missingSeq.count(seqNo) > 0) {
                        if (onlyMissing && (seqNo == lastSeqNo)) {
                            send_hdr->flags = htons(PacketFlags::LAST_DATA); // Set LAST_DATA flag
                                                                             // for the last chunk
                        }

                        int sent_bytes =
                            crypto_sendto(sockfd, send_buffer, sizeof(packet_hdr) + chunk_size, 0,
                                          (struct sockaddr *)&client_addr, addr_len, cipher);
                        if (sent_bytes < 0) {
                            std::cerr << "Error sending file data" << std::endl;
                            break; // Exit on send error
                        }
                        ++sent;

                        // emprerical delay to to avoid loses for big files
                        if (sent > 30) {
                            sent = 0;
                            std::this_thread::sleep_for(std::chrono::milliseconds(30));
                        }

                        // std::cout << "File " << file_path << ", seqNo=" << seqNo <<",
                        // sent successfully, sent " << (sizeof(packet_hdr) + chunk_size) <<
                        // " bytes." << std::endl;
                    }
                    file_size -= chunk_size;
                    offset += chunk_size;

                    ++seqNo;

                    if (file_size == 0)
                        break;
                }
            }).detach();
        } else if (hdr->type == PacketType::WRITE_FILE) {
            // std::cout << "Processing WRITE_FILE request for URI: " << hdr->uri <<
            // ", seqNo: " << hdr->seqNo << std::endl;

            bool firstPacket = false;
            if (!writeData.count(file_path)) {
                // not yet data for this file
                firstPacket = true;

                if ((hdr->flags & PacketFlags::LAST_DATA) &&
                    !(hdr->flags & PacketFlags::FIRST_DATA)) {
                    // second last packet - ignore
                    std::cout << "ignore second last packet\n";
                    continue;
                }
            }

            SessionData data;
            memcpy(data.buffer, recv_buffer + sizeof(packet_hdr), hdr->length);
            data.length = hdr->length;
            data.seqNo = hdr->seqNo;
            data.last =
                ((hdr->flags & PacketFlags::LAST_DATA) && !(hdr->flags & PacketFlags::SEQ_NO))
                    ? true
                    : false;
            writeData[file_path].packets.push_back(data);

            if (firstPacket) {
                // not yet data for this file - start cleanup task in case the last
                // packet will be lost
                writeData[file_path].erasure_token = std::make_shared<bool>(true);
                std::thread(writeDataCleaupTask, std::string(file_path),
                            std::weak_ptr<bool>(writeData[file_path].erasure_token))
                    .detach();
            }

            if (hdr->flags & PacketFlags::LAST_DATA) {
                if (!writeData[file_path].started) {
                    std::string path(file_path);
                    packet_hdr send_hdr2 = *send_hdr;
                    // save asynchronously with a delay in case some remaining packets can
                    // be received

                    writeData[file_path].started = true;

                    std::thread([path, sockfd, send_hdr2, client_addr, addr_len, &cipher] {
                        uint8_t send_buffer[MAX_PACKET_SIZE];
                        std::this_thread::sleep_for(500ms); // 0.5 second delay

                        if (!writeData.count(path)) {
                            writeData[path].started = false;
                            std::cerr << "No packets to write for file " << path << "\n";
                            return;
                        }
                        // write file
                        std::vector<SessionData> &packets = writeData[path].packets;
                        // std::cout << "Write " << packets.size() << " packets\n";

                        // Sort in ascending order by seqNo
                        std::sort(packets.begin(), packets.end(),
                                  [](const SessionData &a, const SessionData &b) {
                                      return a.seqNo < b.seqNo;
                                  });

                        uint16_t seq = 0;

                        std::unordered_set<int> missingSeq;
                        for (const auto &packet : packets) {
                            while (packet.seqNo > seq) {
                                missingSeq.insert(seq);
                                std::cerr << "missing: " << seq << std::endl;
                                seq++;
                            }
                            seq = packet.seqNo + 1; // Move to the next expected

                            if (packet.last) {
                                break;
                            }
                        }

                        if (!missingSeq.empty()) {
                            writeData[path].started = false;

                            if (missingSeq.size() > 200) {
                                std::cerr << "Too many missing packets for: " << path << std::endl;
                                reply_error(sockfd, client_addr, addr_len, PacketType::WRITE_FILE,
                                            "Can't write file - too many loses", cipher);
                                writeData.erase(path);
                                return;
                            }
                            // send new request
                            memcpy(send_buffer, &send_hdr2, sizeof(send_hdr2));
                            packet_hdr *send_hdr = reinterpret_cast<packet_hdr *>(send_buffer);

                            send_hdr->flags = htons(PacketFlags::SEQ_NO);
                            send_hdr->length = htons(missingSeq.size() * 2);
                            uint16_t *p =
                                reinterpret_cast<uint16_t *>(send_buffer + sizeof(packet_hdr));
                            for (const int seq : missingSeq) {
                                *p = htons(seq);
                                ++p;
                            }
                            crypto_sendto(sockfd, send_buffer,
                                          sizeof(packet_hdr) + missingSeq.size() * 2, 0,
                                          (struct sockaddr *)&client_addr, addr_len, cipher);

                            return;
                        }

                        // open file for write and append, or create file
                        std::ofstream outFile;
                        outFile.open(path, std::ios::binary | std::ios::trunc);
                        if (!outFile) {
                            writeData[path].started = false;
                            std::cerr << "Failed to open file for writing: " << path << std::endl;
                            reply_error(sockfd, client_addr, addr_len, PacketType::WRITE_FILE,
                                        "Can't open file for writing", cipher);
                            return;
                        }

                        seq = 0;
                        for (const SessionData &packet : packets) {
                            if (packet.seqNo != seq) {
                                std::cerr << "Seq No mismatch: " << path << ", " << packet.seqNo
                                          << " != " << seq << std::endl;
                                reply_error(sockfd, client_addr, addr_len, PacketType::WRITE_FILE,
                                            "Can't write file", cipher);
                                break;
                            }

                            ++seq;

                            outFile.write(reinterpret_cast<const char *>(packet.buffer),
                                          packet.length);

                            if (packet.last) {
                                break;
                            }
                        }

                        outFile.close();

                        writeData.erase(path);

                        memcpy(send_buffer, &send_hdr2, sizeof(send_hdr2));
                        packet_hdr *send_hdr = reinterpret_cast<packet_hdr *>(send_buffer);

                        // reply for ACK
                        send_hdr->flags = 0;
                        send_hdr->length = 0;
                        crypto_sendto(sockfd, send_buffer, sizeof(packet_hdr), 0,
                                      (struct sockaddr *)&client_addr, addr_len, cipher);
                        writeData[path].started = false;
                    }).detach();
                }
            }
        } else if (hdr->type == PacketType::DELETE_FILE) {
            std::cout << "Processing DELETE_FILE request for URI: " << hdr->uri << std::endl;

            try {
                if (!fs::exists(file_path)) {
                    std::cerr << "Path does not exist.\n";
                    reply_error(sockfd, client_addr, addr_len, hdr->type, "Path does not exist",
                                cipher);
                    continue; // Skip processing this packet
                }

                if (fs::is_regular_file(file_path)) {
                    if (std::filesystem::remove(file_path)) {
                        std::cout << "File " << file_path << " deleted successfully.\n";
                    } else {
                        std::cout << "Failed to delete the file: " << file_path << "\n";
                        reply_error(sockfd, client_addr, addr_len, hdr->type, "Can't delete file",
                                    cipher);
                        continue;
                    }
                } else if (fs::is_directory(file_path)) {
                    if (std::filesystem::remove_all(file_path)) {
                        std::cout << "Directory " << file_path << " deleted successfully.\n";
                    } else {
                        std::cout << "Failed to delete the directory: " << file_path << "\n";
                        reply_error(sockfd, client_addr, addr_len, hdr->type,
                                    "Can't delete directory", cipher);
                        continue;
                    }
                }
            } catch (const std::filesystem::filesystem_error &e) {
                std::cerr << "Filesystem error: " << e.what() << '\n';
                reply_error(sockfd, client_addr, addr_len, hdr->type, "Error during deleting",
                            cipher);
                continue;
            }

            send_hdr->flags = 0;
            send_hdr->length = 0;

            crypto_sendto(sockfd, send_buffer, sizeof(packet_hdr) + sizeof(file_info), 0,
                          (const struct sockaddr *)&client_addr, addr_len, cipher);
        } else if (hdr->type == PacketType::LIST_FILES) {
            std::cout << "Processing LIST_FILES request" << std::endl;
            auto files = listDirectory(file_path);

            std::unordered_set<int> missingSeq;
            bool onlyMissing = false;
            uint16_t lastSeqNo = 0;
            if (hdr->flags & PacketFlags::SEQ_NO) {
                onlyMissing = true;
                size_t count = hdr->length / 2;
                std::cout << "MISS[" << count << "]: ";
                uint16_t *pSeq = reinterpret_cast<uint16_t *>(recv_buffer + sizeof(packet_hdr));
                for (size_t i = 0; i < count; ++i) {
                    uint16_t val = ntohs(pSeq[i]);
                    missingSeq.insert(val);
                    std::cout << val << ", ";
                    if (val > lastSeqNo)
                        lastSeqNo = val;
                }
                std::cout << " lastSeqNo=" << lastSeqNo << "\n";
            }

            send_hdr->flags = 0;

            // packet files in format: items num (byte), file type (byte), name length
            // (byte), name bytes

            size_t count = 0; // inside one packet
            size_t added = 0; // total
            uint16_t seqNo = 0;
            size_t maxSize = sizeof(send_buffer) - sizeof(packet_hdr);
            size_t packed = 1; // first byte is num of entries
            uint8_t *p = send_buffer + sizeof(packet_hdr) + 1;
            for (const auto &f : files) {
                // std::cout << "File: " << f.name << ", type: " << f.type << "\n";
                if ((packed + f.name.length() + 2) > maxSize) {
                    // cannot pack next - send packet
                    p = send_buffer + sizeof(packet_hdr);
                    *p = count;
                    ++p;
                    send_hdr->length = htons(packed);
                    send_hdr->seqNo = htons(seqNo);
                    if (added == files.size()) {
                        send_hdr->flags = htons(PacketFlags::LAST_DATA);
                    }

                    if (!onlyMissing || missingSeq.count(seqNo) > 0) {
                        if (onlyMissing && (seqNo == lastSeqNo)) {
                            send_hdr->flags = htons(PacketFlags::LAST_DATA); // Set LAST_DATA flag
                                                                             // for the last chunk
                        }
                        crypto_sendto(sockfd, send_buffer, sizeof(packet_hdr) + packed, 0,
                                      (const struct sockaddr *)&client_addr, addr_len, cipher);
                    }

                    ++seqNo;

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

            if (count > 0 || files.size() == 0) {
                // send rest

                // set count:
                p = send_buffer + sizeof(packet_hdr);
                *p = count;

                send_hdr->length = htons(packed);
                send_hdr->flags = htons(PacketFlags::LAST_DATA);
                send_hdr->seqNo = htons(seqNo);

                if (!onlyMissing || missingSeq.count(seqNo) > 0) {
                    if (onlyMissing && (seqNo == lastSeqNo)) {
                        send_hdr->flags = htons(PacketFlags::LAST_DATA); // Set LAST_DATA flag for
                                                                         // the last chunk
                    }
                    crypto_sendto(sockfd, send_buffer, sizeof(packet_hdr) + packed, 0,
                                  (const struct sockaddr *)&client_addr, addr_len, cipher);
                    std::cout << "Sent last: total=" << added << ", packed=" << packed
                              << ", flags=" << ntohs(send_hdr->flags) << "\n";
                }
            }
        } else if (hdr->type == PacketType::FILE_INFO) {
            std::cout << "Processing FILE_INFO request for URI: " << hdr->uri << std::endl;
            fs::path fpath(file_path);

            if (!fs::exists(file_path)) {
                std::cerr << "Path does not exist.\n";
                reply_error(sockfd, client_addr, addr_len, hdr->type, "Path does not exist",
                            cipher);
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

            sent_bytes = crypto_sendto(sockfd, send_buffer, sizeof(packet_hdr) + sizeof(file_info),
                                       0, (const struct sockaddr *)&client_addr, addr_len, cipher);
            if (sent_bytes < 0) {
                std::cerr << "Error sending file info" << std::endl;
                continue; // Exit on send error
            }
            // std::cout << "File info sent successfully for " << file_path << " sent
            // " << sent_bytes << " bytes." << std::endl; std::cout << "Sent " <<
            // sizeof(packet_hdr) + sizeof(file_info) << " bytes in response." <<
            // std::endl;
        } else if (hdr->type == PacketType::CREATE_DIRECTORY) {
            if (fs::create_directory(file_path)) {
                std::cout << "Directory created: " << file_path << '\n';
                send_hdr->flags = 0;
                send_hdr->length = 0;
                sent_bytes = crypto_sendto(sockfd, send_buffer, sizeof(packet_hdr), 0,
                                           (struct sockaddr *)&client_addr, addr_len, cipher);
            } else {
                std::cerr << "Can't create directory: " << file_path << '\n';
                reply_error(sockfd, client_addr, addr_len, hdr->type, "Can't create directory",
                            cipher);
            }
        } else if (hdr->type == PacketType::RENAME_FILE) {
            char newName[255] = {0};
            try {

                memcpy(newName, recv_buffer + sizeof(packet_hdr), hdr->length);
                if (!fs::exists(file_path)) {
                    std::cerr << "Path does not exist.\n";
                    reply_error(sockfd, client_addr, addr_len, hdr->type, "Path does not exist",
                                cipher);
                    continue; // Skip processing this packet
                }

                std::filesystem::rename(file_path, newName);
            } catch (const std::filesystem::filesystem_error &e) {
                std::cerr << "Filesystem error on rename from " << file_path << " to " << newName
                          << ": " << e.what() << '\n';
                reply_error(sockfd, client_addr, addr_len, hdr->type, "Error during renaming",
                            cipher);
                continue;
            }

            send_hdr->flags = 0;
            send_hdr->length = 0;

            crypto_sendto(sockfd, send_buffer, sizeof(packet_hdr) + sizeof(file_info), 0,
                          (const struct sockaddr *)&client_addr, addr_len, cipher);
        } else if (hdr->type == PacketType::SEARCH_FILES) {
            char pattern[255] = {0};
            char mask[255] = {0};
            char exclude[255] = {0};
            std::vector<std::string> excludes;

            uint8_t *p = recv_buffer + sizeof(packet_hdr);
            uint8_t maskLen = *p;
            ++p;
            memcpy(mask, p, maskLen);
            p += maskLen;

            uint8_t patternLen = *p;
            ++p;
            memcpy(pattern, p, patternLen);
            p += patternLen;

            // process excludes
            while (*p != 0) {
                uint8_t exLen = *p;
                ++p;
                memcpy(exclude, p, exLen);
                exclude[exLen] = 0;
                p += exLen;

                excludes.push_back(std::string(exclude));

                if (p > recv_buffer + sizeof(recv_buffer)) {
                    std::cerr << "Wrong exclude list! \n";
                    break;
                }
            }

            bool case_sens = hdr->flags & PacketFlags::CASE_SENSITIVE;
            bool whole_word = hdr->flags & PacketFlags::WHOLE_WORD;
            bool regex = hdr->flags & PacketFlags::REGEX;

            std::cout << "SEARCH_FILES: mask=" << mask << ", pattern=" << pattern << ", in "
                      << file_path << "\n";
            for (const auto &ex : excludes) {
                std::cout << "Exclude: " << ex << "\n";
            }

            std::vector<std::regex> excludeRegexes;
            for (const auto &p : excludes) {
                excludeRegexes.push_back(globToRegex(p));
            }

            auto [pathStr, maskStr] = splitPathAndMask(mask);

            std::string folder = std::string(file_path);
            if (!pathStr.empty())
                folder += "/" + pathStr;
            if (maskStr.empty()) {
                maskStr = "*";
            } else {
                maskStr = "*" + maskStr + "*";
            }

            std::string pat(pattern);
            packet_hdr saved_send_hdr = *send_hdr;
            std::string maskStr2 = maskStr;
            std::string maskOrig(mask);
            std::string path(file_path);
            std::thread([folder, maskStr2, maskOrig, pat, excludeRegexes, case_sens, whole_word,
                         regex, saved_send_hdr, sockfd, client_addr, addr_len, path, &cipher] {
                std::vector<SearchResult> results;
                uint8_t send_buffer[MAX_PACKET_SIZE];
                packet_hdr *send_hdr = reinterpret_cast<packet_hdr *>(send_buffer);
                memcpy(send_hdr, &saved_send_hdr, sizeof(packet_hdr));
                search_files(folder, maskStr2, pat, excludeRegexes, case_sens, whole_word, regex,
                             results);

                if (pat.empty() && results.empty()) {
                    // no files found - try by relative path,
                    // this is used to open links from terminal
                    search_for_file(path, maskOrig, excludeRegexes, results);
                }

                send_hdr->flags = 0;

                // total(1), path_len (1), path (1..255), line no (2), line_len (1),
                // line (1..255)

                size_t count = 0; // inside one packet
                size_t added = 0; // total
                uint16_t seqNo = 0;
                size_t maxSize = sizeof(send_buffer) - sizeof(packet_hdr);
                size_t packed = 1; // first byte is num of entries
                uint8_t *p = send_buffer + sizeof(packet_hdr) + 1;
                for (const auto &r : results) {
                    std::string newPath = r.path.substr(path.length());
                    if (!newPath.empty() && (newPath[0] == '/' || newPath[0] == '\\')) {
                        newPath.erase(0, 1);
                    }

                    size_t entryLen = r.line.length() + newPath.length() + 4; // 2 x len + lineNo(2)

                    if ((packed + entryLen) > maxSize) {
                        // cannot pack next - send packet
                        p = send_buffer + sizeof(packet_hdr);
                        *p = count;
                        ++p;
                        send_hdr->length = htons(packed + 1);
                        send_hdr->seqNo = htons(seqNo++);
                        if (added == results.size()) {
                            send_hdr->flags = htons(PacketFlags::LAST_DATA);
                        }
                        crypto_sendto(sockfd, send_buffer, sizeof(packet_hdr) + packed, 0,
                                      (const struct sockaddr *)&client_addr, addr_len, cipher);

                        count = 0;
                        packed = 1;
                    }
                    *p = newPath.length();
                    ++p;
                    memcpy(p, newPath.c_str(), newPath.length());
                    p += newPath.length();
                    *((uint16_t *)p) = htons(r.lineNo);
                    p += 2;
                    *p = r.line.length();
                    ++p;
                    memcpy(p, r.line.c_str(), r.line.length());
                    p += r.line.length();

                    packed += (4 + newPath.length() + r.line.length());

                    ++count;
                    ++added;
                }

                if (count > 0 || results.empty()) {
                    // send rest

                    // set count:
                    p = send_buffer + sizeof(packet_hdr);
                    *p = count;

                    send_hdr->length = htons(packed + 1);
                    send_hdr->flags = htons(PacketFlags::LAST_DATA);
                    send_hdr->seqNo = htons(seqNo++);
                    crypto_sendto(sockfd, send_buffer, sizeof(packet_hdr) + packed, 0,
                                  (const struct sockaddr *)&client_addr, addr_len, cipher);
                    std::cout << "Sent last: total=" << added << ", packed=" << packed
                              << ", flags=" << ntohs(send_hdr->flags) << "\n";
                }
            }).detach();
        } else if (hdr->type == PacketType::SEARCH_DEFINITION) {
            char pattern[255] = {0};

            uint8_t *p = recv_buffer + sizeof(packet_hdr);
            uint8_t patternLen = *p;
            ++p;
            memcpy(pattern, p, patternLen);
            p += patternLen;

            std::cout << "SEARCH_DEFINITION: pattern=" << pattern << ", in " << file_path
                      << "/.tags \n";

            std::string path = std::string(file_path) + "/.tags";

            if (!fs::exists(path)) {
                std::cerr << "Path " << path << " does not exist.\n";
                reply_error(sockfd, client_addr, addr_len, hdr->type,
                            "'.tags' is not exists, run: ctags -R -f .tags", cipher);
                continue; // Skip processing this packet
            }

            std::string pat(pattern);
            packet_hdr saved_send_hdr = *send_hdr;
            std::thread([sockfd, client_addr, addr_len, &cipher, path, pat, saved_send_hdr] {
                uint8_t send_buffer[MAX_PACKET_SIZE];
                packet_hdr *send_hdr = reinterpret_cast<packet_hdr *>(send_buffer);
                memcpy(send_hdr, &saved_send_hdr, sizeof(packet_hdr));

                std::vector<std::string> results = fast_grep_tags(path, pat);

                send_hdr->flags = 0;

                // total(1), line_len (1), line (1..255)

                size_t count = 0; // inside one packet
                size_t added = 0; // total
                uint16_t seqNo = 0;
                size_t maxSize = sizeof(send_buffer) - sizeof(packet_hdr);
                size_t packed = 1; // first byte is num of entries
                uint8_t *p = send_buffer + sizeof(packet_hdr) + 1;
                for (const auto &r : results) {
                    std::string line = r.substr(0, 255);
                    size_t entryLen = line.length() + 1;

                    if ((packed + entryLen) > maxSize) {
                        // cannot pack next - send packet
                        p = send_buffer + sizeof(packet_hdr);
                        *p = count;
                        ++p;
                        send_hdr->length = htons(packed + 1);
                        send_hdr->seqNo = htons(seqNo++);
                        if (added == results.size()) {
                            send_hdr->flags = htons(PacketFlags::LAST_DATA);
                        }
                        crypto_sendto(sockfd, send_buffer, sizeof(packet_hdr) + packed, 0,
                                      (const struct sockaddr *)&client_addr, addr_len, cipher);

                        count = 0;
                        packed = 1;
                    }
                    *p = line.length();
                    ++p;
                    memcpy(p, line.c_str(), line.length());
                    p += line.length();

                    packed += (1 + line.length());

                    ++count;
                    ++added;
                }

                if (count > 0 || results.empty()) {
                    // set count:
                    p = send_buffer + sizeof(packet_hdr);
                    *p = count;

                    send_hdr->length = htons(packed + 1);
                    send_hdr->flags = htons(PacketFlags::LAST_DATA);
                    send_hdr->seqNo = htons(seqNo++);
                    crypto_sendto(sockfd, send_buffer, sizeof(packet_hdr) + packed, 0,
                                  (const struct sockaddr *)&client_addr, addr_len, cipher);
                    std::cout << "Sent last: total=" << added << ", packed=" << packed
                              << ", flags=" << ntohs(send_hdr->flags) << "\n";
                }
            }).detach();
        }

        else {
            std::cerr << "Unknown packet type received" << std::endl;
        }
    }

    close(sockfd);
    return 0;
}

static void reply_error(int sockfd, const struct sockaddr_in &cliaddr, socklen_t len, uint8_t type,
                        const char *msg, AESCipher &cipher) {
    uint8_t reply[1024];
    struct packet_hdr *hdr = reinterpret_cast<struct packet_hdr *>(reply);
    hdr->version = 1;
    hdr->type = type;
    hdr->flags = htons(PacketFlags::ERROR);
    hdr->length = htons(strlen(msg) + 1);
    memcpy(reply + sizeof(struct packet_hdr), msg, strlen(msg) + 1);
    crypto_sendto(sockfd, reply, sizeof(struct packet_hdr) + strlen(msg) + 1, 0,
                  (const struct sockaddr *)&cliaddr, len, cipher);
}

static int crypto_sendto(int sockfd, const uint8_t *buf, size_t len, int flags,
                         const struct sockaddr *dest_addr, socklen_t addrlen, AESCipher &cipher) {
    const packet_hdr *hdr = reinterpret_cast<const packet_hdr *>(buf);
    bool last = ntohs(hdr->flags) & PacketFlags::LAST_DATA;

    std::vector<uint8_t> encrypted_data = cipher.encrypt(buf, len);

    if (last) {
        // Send last packet twice for reliability:
        struct sockaddr_in addr = *reinterpret_cast<const struct sockaddr_in *>(dest_addr);
        auto lambda = [sockfd, encrypted_data, addr, addrlen]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            sendto(sockfd, encrypted_data.data(), encrypted_data.size(), 0,
                   (const struct sockaddr *)&addr, addrlen);
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            sendto(sockfd, encrypted_data.data(), encrypted_data.size(), 0,
                   (const struct sockaddr *)&addr, addrlen);
        };

        std::thread t(lambda);
        t.detach();
    } else {
        return sendto(sockfd, encrypted_data.data(), encrypted_data.size(), flags, dest_addr,
                      addrlen);
    }

    return len;
}

#if 0
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
#endif