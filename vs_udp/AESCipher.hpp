#ifndef _AES_CIPHER_HPP_
#define _AES_CIPHER_HPP_

#include <openssl/evp.h>
#include <vector>
#include <cstdint>
#include <cstring>
#include <stdexcept>

class AESCipher {
public:
    AESCipher(const uint8_t key[32], const uint8_t iv[16])
        : key_(key, key + 32), iv_(iv, iv + 16) {
        if (key_.size() != 32 || iv_.size() != 16) {
            throw std::runtime_error("Invalid key or IV size");
        }
    }

    std::vector<uint8_t> encrypt(const uint8_t* data, size_t len) const {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_.data(), iv_.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EncryptInit failed");
        }

        std::vector<uint8_t> encrypted(len + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
        int out_len1 = 0;
        if (EVP_EncryptUpdate(ctx, encrypted.data(), &out_len1, data, len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EncryptUpdate failed");
        }

        int out_len2 = 0;
        if (EVP_EncryptFinal_ex(ctx, encrypted.data() + out_len1, &out_len2) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EncryptFinal failed");
        }

        encrypted.resize(out_len1 + out_len2);
        EVP_CIPHER_CTX_free(ctx);
        return encrypted;
    }

    std::vector<uint8_t> decrypt(const uint8_t* data, size_t len) const {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_.data(), iv_.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("DecryptInit failed");
        }

        std::vector<uint8_t> decrypted(len);
        int out_len1 = 0;
        if (EVP_DecryptUpdate(ctx, decrypted.data(), &out_len1, data, len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("DecryptUpdate failed");
        }

        int out_len2 = 0;
        if (EVP_DecryptFinal_ex(ctx, decrypted.data() + out_len1, &out_len2) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("DecryptFinal failed");
        }

        decrypted.resize(out_len1 + out_len2);
        EVP_CIPHER_CTX_free(ctx);
        return decrypted;
    }

private:
    std::vector<uint8_t> key_;
    std::vector<uint8_t> iv_;
};
#endif