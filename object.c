
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).

//:)
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // Map type enum to string
    const char *type_str;
    switch (type) {
        case OBJ_BLOB:   type_str = "blob";   break;
        case OBJ_TREE:   type_str = "tree";   break;
        case OBJ_COMMIT: type_str = "commit"; break;
        default: return -1;
    }

    // Build header: "type size" (without the \0 yet — snprintf adds one but
    // we capture the byte length and embed the \0 manually below)
    char header_str[64];
    int header_len = snprintf(header_str, sizeof(header_str), "%s %zu", type_str, len);
    if (header_len < 0 || (size_t)header_len >= sizeof(header_str)) return -1;

    // Allocate full buffer: header bytes + '\0' separator + data
    size_t full_len = (size_t)header_len + 1 + len;
    unsigned char *buf = malloc(full_len);
    if (!buf) return -1;

    memcpy(buf, header_str, (size_t)header_len);   // "blob 16"
    buf[header_len] = '\0';                          // literal null byte separator
    memcpy(buf + header_len + 1, data, len);         // raw data

    // Hash the FULL buffer (header + '\0' + data)
    compute_hash(buf, full_len, id_out);

    // Deduplication: if already stored, skip write
    if (object_exists(id_out)) {
        free(buf);
        return 0;
    }

    // Build paths
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);

    char shard_dir[512];
    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);

    char final_path[512];
    object_path(id_out, final_path, sizeof(final_path));

    char tmp_path[520];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", final_path);

    // Create shard directory (ignore EEXIST)
    if (mkdir(shard_dir, 0755) < 0 && errno != EEXIST) {
        free(buf);
        return -1;
    }

    // Write to temp file (mode 0644: immutable once written, like Git)
    int fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { free(buf); return -1; }

    size_t written = 0;
    while (written < full_len) {
        ssize_t n = write(fd, buf + written, full_len - written);
        if (n < 0) { close(fd); unlink(tmp_path); free(buf); return -1; }
        written += (size_t)n;
    }

    free(buf);

    if (fsync(fd) < 0) { close(fd); unlink(tmp_path); return -1; }
    close(fd);

    // Atomic rename temp -> final path
    if (rename(tmp_path, final_path) < 0) { unlink(tmp_path); return -1; }

    // fsync the shard directory to persist the directory entry
    int dir_fd = open(shard_dir, O_RDONLY);
    if (dir_fd >= 0) { fsync(dir_fd); close(dir_fd); }

    return 0;
}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // Step 1: Resolve the path and open the file
    char path[512];
    object_path(id, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    // Step 2: Read the entire file into memory
    if (fseek(f, 0, SEEK_END) < 0) { fclose(f); return -1; }
    long file_sz = ftell(f);
    if (file_sz < 0) { fclose(f); return -1; }
    rewind(f);

    unsigned char *buf = malloc((size_t)file_sz);
    if (!buf) { fclose(f); return -1; }

    if (fread(buf, 1, (size_t)file_sz, f) != (size_t)file_sz) {
        free(buf); fclose(f); return -1;
    }
    fclose(f);

    // Step 3: Integrity check — recompute hash over ALL bytes and compare to *id
    ObjectID computed;
    compute_hash(buf, (size_t)file_sz, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(buf); return -1;   // corruption detected
    }

    // Step 4: Find the '\0' separator between header and data
    // Use memchr (not strchr): the data section may itself contain '\0' bytes.
    unsigned char *null_pos = memchr(buf, '\0', (size_t)file_sz);
    if (!null_pos) { free(buf); return -1; }   // malformed: no separator

    // Step 5: Parse the header "type size" in a separate null-terminated buffer
    size_t header_len = (size_t)(null_pos - buf);
    char header[128];
    if (header_len >= sizeof(header)) { free(buf); return -1; }
    memcpy(header, buf, header_len);
    header[header_len] = '\0';

    // Split "blob 42" → type_str, size_str
    char *space = strchr(header, ' ');
    if (!space) { free(buf); return -1; }
    *space = '\0';
    const char *type_str = header;
    const char *size_str = space + 1;

    // Parse declared data size
    char *end_ptr;
    size_t declared_len = (size_t)strtoul(size_str, &end_ptr, 10);
    if (*end_ptr != '\0') { free(buf); return -1; }  // trailing garbage

    // Cross-check declared length vs actual bytes after '\0'
    size_t actual_data_len = (size_t)file_sz - header_len - 1;
    if (declared_len != actual_data_len) { free(buf); return -1; }

    // Step 6: Map type string → ObjectType enum
    ObjectType otype;
    if      (strcmp(type_str, "blob")   == 0) otype = OBJ_BLOB;
    else if (strcmp(type_str, "tree")   == 0) otype = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0) otype = OBJ_COMMIT;
    else { free(buf); return -1; }

    // Step 7: Allocate and copy the data portion (bytes after the '\0')
    void *out = malloc(declared_len + 1);  // +1: convenience null for string callers
    if (!out) { free(buf); return -1; }
    memcpy(out, null_pos + 1, declared_len);
    ((char *)out)[declared_len] = '\0';

    free(buf);

    *type_out = otype;
    *data_out = out;
    *len_out  = declared_len;
    return 0;
}