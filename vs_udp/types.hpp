#ifndef _TYPES_HPP_
#define _TYPES_HPP_


#include <cstdint>

enum PacketType {
    READ_FILE,
    WRITE_FILE,
    DELETE_FILE,
    LIST_FILES,
    FILE_INFO,
    CREATE_DIRECTORY,
    RENAME_FILE,
    SEARCH_FILES,     // search files or text in files
};

enum PacketFlags {
    LAST_DATA = 0x01, // Indicates that this is the last packet of data
    ERROR = 0x02,      // Indicates an error occurred
    FIRST_DATA = 0x04,    // first packet
};

struct packet_hdr {
    uint8_t version;
    uint8_t type;     // packet type PacketType
    uint16_t flags;   // packet flags PacketFlags
    uint8_t  uri[255]; // URI for the file
    uint16_t length;  // Length of the packet data
    uint16_t reqId;   // request ID
    uint16_t seqNo;   // sequence number, starts from 0
   
} __attribute__((packed));

struct file_info {
    uint32_t size;        // Size of the file in bytes
    uint8_t type;         // 0 - unknown, 1 - file, 2 - directory, 64 - symlink
    char ctime[20];       // Creation time in ISO 8601 format
    char mtime[20];       // Last modification time in ISO 8601 format
} __attribute__((packed));


#if 0
class CRC32 {
public:
    CRC32() {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t crc = i;
            for (uint32_t j = 0; j < 8; ++j)
                crc = (crc >> 1) ^ (0xEDB88320 * (crc & 1));
            table[i] = crc;
        }
    }

    uint32_t compute(const std::vector<char>& data) const {
        uint32_t crc = 0xFFFFFFFF;
        for (char byte : data)
            crc = (crc >> 8) ^ table[(crc ^ byte) & 0xFF];
        return crc ^ 0xFFFFFFFF;
    }

private:
    uint32_t table[256];
};
#endif

struct FileEntry {
    std::string name;
    int type; // 1 = file, 2 = directory
};

// used for WRITE_FILE
struct SessionData {
    uint8_t buffer[800];
    uint16_t length;

    uint16_t    seqNo;
};

struct SearchResult
{
    std::string path;
    std::string line;
    uint16_t lineNo;
};

#endif // _TYPES_HPP_
