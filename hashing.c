#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#define SALT_LENGTH 16
#define HASH_LENGTH SHA256_DIGEST_LENGTH

// Convert binary to hex
void to_hex(const unsigned char *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + (i * 2), "%02x", in[i]);
    }
    out[len * 2] = '\0';
}

// Function to hash a password with salt
void hash_password(const char *password, const char *salt, char *hash_out) {
    char salted[512];
    unsigned char hash[HASH_LENGTH];
    
    // Combine salt and password
    sprintf(salted, "%s%s", salt, password);
    
    // Hash the salted password
    SHA256((unsigned char *)salted, strlen(salted), hash);
    
    // Convert hash to hex
    to_hex(hash, HASH_LENGTH, hash_out);
}

int main() {
    const char *password = "@dmin";
    unsigned char salt_bytes[SALT_LENGTH];
    char salt[SALT_LENGTH * 2 + 1];
    char hash[HASH_LENGTH * 2 + 1];

    // Generate random salt
    if (!RAND_bytes(salt_bytes, sizeof(salt_bytes))) {
        perror("Random bytes generation failed");
        exit(EXIT_FAILURE);
    }
    
    // Convert salt to hex
    to_hex(salt_bytes, SALT_LENGTH, salt);

    // Hash the password
    hash_password(password, salt, hash);

    // Print results
    printf("Salt: %s\n", salt);
    printf("Hash: %s\n", hash);

    return 0;
}
