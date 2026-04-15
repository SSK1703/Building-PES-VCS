#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h>

/* --- HELPER FUNCTIONS --- */

// Convert ObjectType enum to string
static const char* type_to_string(ObjectType type) {
    switch (type) {
        case OBJ_BLOB:   return "blob";
        case OBJ_TREE:   return "tree";
        case OBJ_COMMIT: return "commit";
        default:         return "unknown";
    }
}

// Convert string to ObjectType enum
static ObjectType string_to_type(const char *str) {
    if (strcmp(str, "blob") == 0)   return OBJ_BLOB;
    if (strcmp(str, "tree") == 0)   return OBJ_TREE;
    if (strcmp(str, "commit") == 0) return OBJ_COMMIT;
    return -1;  // Invalid type
}

// Convert a binary hash to a 64-character hex string
void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + (i * 2), "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

// Convert hex string to binary ObjectID
int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) != HASH_HEX_SIZE) return -1;
    
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + (i * 2), "%2x", &byte) != 1) {
            return -1;
        }
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

// Get the filesystem path for an object
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, ".pes/objects/%.2s/%s", hex, hex + 2);
}

/* --- OBJECT STORAGE FUNCTIONS --- */

// Write an object to disk and return its ObjectID
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    const char *type_str = type_to_string(type);
    
    // Create header: "type size\0"
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    header[header_len] = '\0';
    header_len++;  // Include null terminator in the header
    
    // Compute SHA-256 hash of "header\0data"
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return -1;
    
    unsigned int md_len;
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, header, header_len);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, id_out->hash, &md_len);
    EVP_MD_CTX_free(mdctx);
    
    // Create object file
    mkdir(".pes", 0755);
    mkdir(".pes/objects", 0755);
    
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);
    
    char dir[256];
    snprintf(dir, sizeof(dir), ".pes/objects/%.2s", hex);
    mkdir(dir, 0755);
    
    char path[512];
    object_path(id_out, path, sizeof(path));
    
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    
    if (fwrite(header, 1, header_len, f) != (size_t)header_len) {
        fclose(f);
        return -1;
    }
    
    if (fwrite(data, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    
    fclose(f);
    return 0;
}

// Read an object from disk
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    char path[512];
    object_path(id, path, sizeof(path));
    
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    
    // Read header until null terminator
    char header[64];
    int i = 0;
    while (i < (int)sizeof(header) - 1) {
        int ch = fgetc(f);
        if (ch == EOF) {
            fclose(f);
            return -1;
        }
        header[i] = (char)ch;
        if (ch == '\0') break;
        i++;
    }
    if (i >= (int)sizeof(header) - 1) {
        fclose(f);
        return -1;
    }
    
    // Parse header
    char type_str[16];
    if (sscanf(header, "%15s %zu", type_str, len_out) != 2) {
        fclose(f);
        return -1;
    }
    
    *type_out = string_to_type(type_str);
    if ((int)*type_out == -1) {
        fclose(f);
        return -1;
    }
    
    // Read data
    *data_out = malloc(*len_out);
    if (!*data_out) {
        fclose(f);
        return -1;
    }
    
    size_t bytes_read = fread(*data_out, 1, *len_out, f);
    fclose(f);
    
    if (bytes_read != *len_out) {
        free(*data_out);
        *data_out = NULL;
        return -1;
    }
    
    // Verify integrity: recompute hash and compare with expected
    int header_len = strlen(header) + 1;  // Include null terminator
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        free(*data_out);
        *data_out = NULL;
        return -1;
    }
    
    ObjectID computed_id;
    unsigned int md_len;
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, header, header_len);
    EVP_DigestUpdate(mdctx, *data_out, *len_out);
    EVP_DigestFinal_ex(mdctx, computed_id.hash, &md_len);
    EVP_MD_CTX_free(mdctx);
    
    // Compare hashes
    if (memcmp(computed_id.hash, id->hash, HASH_SIZE) != 0) {
        free(*data_out);
        *data_out = NULL;
        return -1;
    }
    
    return 0;
}

// Check if an object exists
int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    
    FILE *f = fopen(path, "rb");
    if (f) {
        fclose(f);
        return 1;
    }
    return 0;
}
