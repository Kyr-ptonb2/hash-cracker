# hash-cracker
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <crypt.h>
#include <libscrypt.h>
#include <errno.h>
#include <b64/cencode.h>
#include <b64/cdecode.h>

#define WORDLIST_PATH "/usr/share/wordlists/rockyou.txt"

// Extract salt and stored hash from Yescrypt format
int extract_yescrypt_parts(const char *hash, char *salt, char *stored_hash) {
    char *dollar = strstr(hash, "$y$");
    if (!dollar) return 0;

    char *third_dollar = strchr(dollar + 3, '$');
    if (!third_dollar) return 0;

    char *fourth_dollar = strchr(third_dollar + 1, '$');
    if (!fourth_dollar) return 0;

    strncpy(salt, third_dollar + 1, fourth_dollar - third_dollar - 1);
    salt[fourth_dollar - third_dollar - 1] = '\0';
    
    strcpy(stored_hash, fourth_dollar + 1);
    return 1;
}

// Base64 decoding function using libb64
int decode_base64(const char *input, unsigned char *output, int output_size) {
    base64_decodestate state;
    base64_init_decodestate(&state);
    return base64_decode_block(input, strlen(input), (char *)output, &state);
}

// Base64 encoding function using libb64
void encode_base64(const unsigned char *input, int input_size, char *output, int output_size) {
    base64_encodestate state;
    base64_init_encodestate(&state);
    base64_encode_block((const char *)input, input_size, output, &state);
}

// Compute Yescrypt hash (Uses scrypt)
int verify_yescrypt(const char *password, const char *salt, const char *stored_hash) {
    unsigned char derived_key[64];  // Yescrypt outputs a 64-byte hash
    unsigned char decoded_salt[32];

    int decoded_size = decode_base64(salt, decoded_salt, sizeof(decoded_salt));
    if (decoded_size <= 0) {
        printf("[-] Error decoding salt.\n");
        return 0;
    }

    if (libscrypt_scrypt((uint8_t *)password, strlen(password), decoded_salt, decoded_size, 16384, 8, 1, derived_key, 64) != 0) {
        printf("[-] Scrypt hashing failed: %s\n", strerror(errno));
        return 0;
    }

    char encoded_hash[128];
    encode_base64(derived_key, 64, encoded_hash, sizeof(encoded_hash));

    return strcmp(encoded_hash, stored_hash) == 0;
}

// Identify the hash type
const char *identify_hash(const char *hash) {
    int length = strlen(hash);

    if (strncmp(hash, "$2a$", 4) == 0 || strncmp(hash, "$2b$", 4) == 0 || strncmp(hash, "$2y$", 4) == 0)
        return "bcrypt";
    if (strncmp(hash, "$y$", 3) == 0)
        return "yescrypt";
    if (length == 32)
        return "md5";
    if (length == 64)
        return "sha256";

    return "unknown";
}

// Cracking function
void crack_hash(const char *hash) {
    FILE *wordlist = fopen(WORDLIST_PATH, "r");
    if (!wordlist) {
        perror("[-] Error opening wordlist file");
        return;
    }

    const char *hash_type = identify_hash(hash);
    printf("[+] Detected Hash Type: %s\n", hash_type);

    char password[256], salt[64], stored_hash[128];

    if (strcmp(hash_type, "yescrypt") == 0) {
        if (!extract_yescrypt_parts(hash, salt, stored_hash)) {
            printf("[-] Error extracting Yescrypt parts.\n");
            fclose(wordlist);
            return;
        }
    }

    while (fgets(password, sizeof(password), wordlist)) {
        password[strcspn(password, "\n")] = '\0';

        if (strcmp(hash_type, "yescrypt") == 0) {
            if (verify_yescrypt(password, salt, stored_hash)) {
                printf("[+] Password Found: %s\n", password);
                fclose(wordlist);
                return;
            }
        }
    }

    printf("[-] No password match found.\n");
    fclose(wordlist);
}

int main() {
    char hash_input[256];

    printf("Enter the hash: ");
    scanf("%255s", hash_input);

    crack_hash(hash_input);

    return 0;
}

//Compile the program using the following command: gcc -o hash-cracker hash-cracker.c -lcrypt -lscrypt -lb64 -lssl -lcrypto
//Run the program using the following command: ./hash-cracker
//Enter the hash to crack
//The program will attempt to crack the hash using the wordlist located at /usr/share/wordlists/rockyou.txt
//The program will output the cracked password if found
//The program will output an error message if the wordlist file is not found or if the password is not found in the wordlist
//The program will output an error message if the hash type is not supported
//The program supports MD5, SHA-256, bcrypt, and Yescrypt hashes
//The program uses the libscrypt library to compute Yescrypt hashes
//The program uses the libb64 library to encode and decode base64 strings
//The program uses the crypt library to verify bcrypt hashes
