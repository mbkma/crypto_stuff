#include <iostream>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

bool encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext, int &ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create EVP_CIPHER_CTX" << std::endl;
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) != 1) {
        std::cerr << "Failed to initialize encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len) != 1) {
        std::cerr << "Failed to encrypt data" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext, int &plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create EVP_CIPHER_CTX" << std::endl;
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) != 1) {
        std::cerr << "Failed to initialize decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext, ciphertext_len) != 1) {
        std::cerr << "Failed to decrypt data" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;
}


EVP_PKEY *generate_key_pair() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        std::cerr << "Failed to create EVP_PKEY_CTX" << std::endl;
        return nullptr;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "Failed to initialize keygen" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        std::cerr << "Failed to set key length" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY *key = nullptr;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        std::cerr << "Failed to generate key pair" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return key;
}

bool sign(EVP_PKEY *private_key, const unsigned char *message, int message_len, unsigned char *signature, size_t &signature_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    if (!ctx) {
        std::cerr << "Failed to create EVP_MD_CTX" << std::endl;
        return false;
    }

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, private_key) != 1) {
        std::cerr << "Failed to initialize signing" << std::endl;
        EVP_MD_CTX_destroy(ctx);
        return false;
    }

    if (EVP_DigestSignUpdate(ctx, message, message_len) != 1) {
        std::cerr << "Failed to update signing" << std::endl;
        EVP_MD_CTX_destroy(ctx);
        return false;
    }

    if (EVP_DigestSignFinal(ctx, signature, &signature_len) != 1) {
        std::cerr << "Failed to finalize signing" << std::endl;
        EVP_MD_CTX_destroy(ctx);
        return false;
    }

    EVP_MD_CTX_destroy(ctx);
    return true;
}

bool verify(EVP_PKEY *public_key, const unsigned char *message, int message_len, const unsigned char *signature, unsigned int signature_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    if (!ctx) {
        std::cerr << "Failed to create EVP_MD_CTX" << std::endl;
        return false;
    }

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, public_key) != 1) {
        std::cerr << "Failed to initialize verification" << std::endl;
        EVP_MD_CTX_destroy(ctx);
        return false;
    }

    if (EVP_DigestVerifyUpdate(ctx, message, message_len) != 1) {
        std::cerr << "Failed to update verification" << std::endl;
        EVP_MD_CTX_destroy(ctx);
        return false;
    }

    int result = EVP_DigestVerifyFinal(ctx, signature, signature_len);
    EVP_MD_CTX_destroy(ctx);

    if (result != 1) {
        std::cerr << "Failed to finalize verification" << std::endl;
        return false;
    }

    return true;
}

int
main(int argc, char** argv)
{
    return EXIT_SUCCESS;
}