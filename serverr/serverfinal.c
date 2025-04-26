#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <dirent.h>  
#include <stdbool.h>
#include <fcntl.h>
#include <sys/stat.h>

#define PORT 8080
#define BUFFER_SIZE 2048
#define HASH_LENGTH 32
#define MAX_CLIENTS 10

int client_counter = 0;
pthread_mutex_t counter_lock;
pthread_mutex_t file_lock;

// Send message to socket
void send_message(int socket, unsigned char *data, int len) {
    uint32_t net_len = htonl(len);
    send(socket, &net_len, sizeof(net_len), 0);
    if (send(socket, data, len, 0) < 0) {
        perror("Send failed");
        exit(EXIT_FAILURE);
    }
}

// Read message from socket
int read_message(int socket, unsigned char *buffer, const char *error_msg) {
    uint32_t net_len;
    if (recv(socket, &net_len, sizeof(net_len), MSG_WAITALL) <= 0) {
        perror("Read length failed");
        exit(EXIT_FAILURE);
    }
    int len = ntohl(net_len);
    if (recv(socket, buffer, len, MSG_WAITALL) <= 0) {
        perror(error_msg);
        exit(EXIT_FAILURE);
    }
    return len;
}

// Convert binary to hex string
void convert_to_hex(const unsigned char *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + (i * 2), "%02x", in[i]);
    }
    out[len * 2] = '\0';
}

// Print data in hex format 
void print_hex(char *log, const char *label, unsigned char *data, int len) {
    char hex[BUFFER_SIZE * 2];
    int pos = 0;
    pos += snprintf(hex, sizeof(hex), "%s", label);
    for (int i = 0; i < len; i++) {
        pos += snprintf(hex + pos, sizeof(hex) - pos, "%02X", data[i]);
    }
    snprintf(log + strlen(log), BUFFER_SIZE * 4 - strlen(log), "%s\n", hex);
}

// Authenticate user and get role
int authenticate(const char username[], const char password[], char *role_out) {
    FILE *file = fopen("credentials.txt", "r");
    if (!file) return 0;

    char line[BUFFER_SIZE], stored_user[50], stored_salt[33], stored_hash[65], computed_hash[65], stored_role[20];

    while (fgets(line, sizeof(line), file)) {
        sscanf(line, "%s %s %s %s", stored_user, stored_salt, stored_hash, stored_role);
        if (strcmp(username, stored_user) == 0) {
            char salted[512];
            unsigned char hash[HASH_LENGTH];
            sprintf(salted, "%s%s", stored_salt, password);
            SHA256((unsigned char *)salted, strlen(salted), hash);
            convert_to_hex(hash, HASH_LENGTH, computed_hash);

            if (strcmp(computed_hash, stored_hash) == 0) {
                strcpy(role_out, stored_role);
                fclose(file);
                return 1;
            } else {
                fclose(file);
                return 0;
            }
        }
    }

    fclose(file);
    return 0;
}


// Encrypt data using AES-GCM
int encrypt_gcm(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv,
                unsigned char *ciphertext, unsigned char *auth_tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int enc_len, final_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &enc_len, plaintext, plaintext_len);
    EVP_EncryptFinal_ex(ctx, ciphertext + enc_len, &final_len);
    enc_len += final_len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, auth_tag);
    EVP_CIPHER_CTX_free(ctx);
    return enc_len;
}

// Decrypt data using AES-GCM
int decrypt_gcm(unsigned char *enc_buf, int enc_len,
                unsigned char *auth_tag, unsigned char *key, unsigned char *iv,
                unsigned char *dec_buf) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, total_len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, dec_buf, &len, enc_buf, enc_len);
    total_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, auth_tag);

    if (EVP_DecryptFinal_ex(ctx, dec_buf + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    total_len += len;
    dec_buf[total_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);
    return total_len;
}


// Handle file download request
void handle_file_download(int client_fd, const char *filepath, const char *filename, unsigned char *key, unsigned char *iv) {
    pthread_mutex_lock(&file_lock);

    // Check if file exists
    if (access(filepath, F_OK) != 0) {
        char error_msg[BUFFER_SIZE];
        snprintf(error_msg, sizeof(error_msg), "Error: File '%s' does not exist on server", filename);
        
        unsigned char buffer[BUFFER_SIZE], tag[16];
        int len = encrypt_gcm((unsigned char *)error_msg, strlen(error_msg), key, iv, buffer, tag);
        send_message(client_fd, buffer, len);
        send_message(client_fd, tag, 16);
        pthread_mutex_unlock(&file_lock);
        return;
    }

    // Open and read the file
    FILE *file = fopen(filepath, "r");
    if (!file) {
        char error_msg[BUFFER_SIZE];
        snprintf(error_msg, sizeof(error_msg), "Error: Could not open file '%s' for reading", filename);
        
        unsigned char buffer[BUFFER_SIZE], tag[16];
        int len = encrypt_gcm((unsigned char *)error_msg, strlen(error_msg), key, iv, buffer, tag);
        send_message(client_fd, buffer, len);
        send_message(client_fd, tag, 16);
        pthread_mutex_unlock(&file_lock);
        return;
    }

    // Read file content
    char content[BUFFER_SIZE];
    size_t bytes_read = fread(content, 1, sizeof(content) - 1, file);
    content[bytes_read] = '\0';
    fclose(file);

    // Send success message first
    char success_msg[BUFFER_SIZE];
    snprintf(success_msg, sizeof(success_msg), "SUCCESS");
    
    unsigned char buffer[BUFFER_SIZE], tag[16];
    int len = encrypt_gcm((unsigned char *)success_msg, strlen(success_msg), key, iv, buffer, tag);
    send_message(client_fd, buffer, len);
    send_message(client_fd, tag, 16);

    // Then send the file content
    len = encrypt_gcm((unsigned char *)content, strlen(content), key, iv, buffer, tag);
    send_message(client_fd, buffer, len);
    send_message(client_fd, tag, 16);
    pthread_mutex_unlock(&file_lock);
}

// Handle file upload request
void handle_file_upload(int client_fd, const char *filepath, const char *filename, const char *content, unsigned char *key, unsigned char *iv) {
    pthread_mutex_lock(&file_lock);

    // Check if file already exists
    if (access(filepath, F_OK) == 0) {
        char error_msg[BUFFER_SIZE];
        snprintf(error_msg, sizeof(error_msg), "Error: File '%s' already exists in server", filename);
        
        unsigned char buffer[BUFFER_SIZE], tag[16];
        int len = encrypt_gcm((unsigned char *)error_msg, strlen(error_msg), key, iv, buffer, tag);
        send_message(client_fd, buffer, len);
        send_message(client_fd, tag, 16);
        pthread_mutex_unlock(&file_lock);
        return;
    }

    // Create and write to the file
    FILE *file = fopen(filepath, "w");
    if (!file) {
        char error_msg[BUFFER_SIZE];
        snprintf(error_msg, sizeof(error_msg), "Error: Could not create file '%s' on server", filename);
        
        unsigned char buffer[BUFFER_SIZE], tag[16];
        int len = encrypt_gcm((unsigned char *)error_msg, strlen(error_msg), key, iv, buffer, tag);
        send_message(client_fd, buffer, len);
        send_message(client_fd, tag, 16);
        pthread_mutex_unlock(&file_lock);
        return;
    }

    // Write the content
    fputs(content, file);
    fclose(file);

    // Send success message
    char success_msg[BUFFER_SIZE];
    snprintf(success_msg, sizeof(success_msg), "File '%s' has been uploaded successfully", filepath);
    
    unsigned char buffer[BUFFER_SIZE], tag[16];
    int len = encrypt_gcm((unsigned char *)success_msg, strlen(success_msg), key, iv, buffer, tag);
    send_message(client_fd, buffer, len);
    send_message(client_fd, tag, 16);
    pthread_mutex_unlock(&file_lock);
}

// Rename file on server
void rename_server_file(int client_fd, const char *old_path, const char *new_path, const char *old_filename, const char *new_filename, unsigned char *key, unsigned char *iv) {
    pthread_mutex_lock(&file_lock);

    // Check if source file exists
    if (access(old_path, F_OK) != 0) {
        char error_msg[BUFFER_SIZE];
        snprintf(error_msg, sizeof(error_msg), "Error: Source file '%s' does not exist", old_filename);
        
        unsigned char buffer[BUFFER_SIZE], tag[16];
        int len = encrypt_gcm((unsigned char *)error_msg, strlen(error_msg), key, iv, buffer, tag);
        send_message(client_fd, buffer, len);
        send_message(client_fd, tag, 16);
        pthread_mutex_unlock(&file_lock);
        return;
    }

    // Check if destination file already exists
    if (access(new_path, F_OK) == 0) {
        char error_msg[BUFFER_SIZE];
        snprintf(error_msg, sizeof(error_msg), "Error: Destination file '%s' already exists", new_filename);
        
        unsigned char buffer[BUFFER_SIZE], tag[16];
        int len = encrypt_gcm((unsigned char *)error_msg, strlen(error_msg), key, iv, buffer, tag);
        send_message(client_fd, buffer, len);
        send_message(client_fd, tag, 16);
        pthread_mutex_unlock(&file_lock);
        return;
    }

    // Try to rename the file
    if (rename(old_path, new_path) != 0) {
        char error_msg[BUFFER_SIZE];
        snprintf(error_msg, sizeof(error_msg), "Error: Could not rename file from '%s' to '%s'", old_filename, new_filename);
        
        unsigned char buffer[BUFFER_SIZE], tag[16];
        int len = encrypt_gcm((unsigned char *)error_msg, strlen(error_msg), key, iv, buffer, tag);
        send_message(client_fd, buffer, len);
        send_message(client_fd, tag, 16);
        pthread_mutex_unlock(&file_lock);
        return;
    }

    // Send success message
    char success_msg[BUFFER_SIZE];
    snprintf(success_msg, sizeof(success_msg), "File successfully renamed from '%s' to '%s'", old_filename, new_filename);
    
    unsigned char buffer[BUFFER_SIZE], tag[16];
    int len = encrypt_gcm((unsigned char *)success_msg, strlen(success_msg), key, iv, buffer, tag);
    send_message(client_fd, buffer, len);
    send_message(client_fd, tag, 16);
    pthread_mutex_unlock(&file_lock);
}

// Delete file from server
void delete_server_file(int client_fd, const char *filepath, const char *filename, unsigned char *key, unsigned char *iv) {
    pthread_mutex_lock(&file_lock);

    // Check if file exists
    if (access(filepath, F_OK) != 0) {
        char error_msg[BUFFER_SIZE];
        snprintf(error_msg, sizeof(error_msg), "Error: File '%s' does not exist", filename);
        
        unsigned char buffer[BUFFER_SIZE], tag[16];
        int len = encrypt_gcm((unsigned char *)error_msg, strlen(error_msg), key, iv, buffer, tag);
        send_message(client_fd, buffer, len);
        send_message(client_fd, tag, 16);
        pthread_mutex_unlock(&file_lock);
        return;
    }

    // Try to delete the file
    if (remove(filepath) != 0) {
        char error_msg[BUFFER_SIZE];
        snprintf(error_msg, sizeof(error_msg), "Error: Could not delete file '%s'", filename);
        
        unsigned char buffer[BUFFER_SIZE], tag[16];
        int len = encrypt_gcm((unsigned char *)error_msg, strlen(error_msg), key, iv, buffer, tag);
        send_message(client_fd, buffer, len);
        send_message(client_fd, tag, 16);
        pthread_mutex_unlock(&file_lock);
        return;
    }

    // Send success message
    char success_msg[BUFFER_SIZE];
    snprintf(success_msg, sizeof(success_msg), "File '%s' has been deleted successfully", filename);
    
    unsigned char buffer[BUFFER_SIZE], tag[16];
    int len = encrypt_gcm((unsigned char *)success_msg, strlen(success_msg), key, iv, buffer, tag);
    send_message(client_fd, buffer, len);
    send_message(client_fd, tag, 16);
    pthread_mutex_unlock(&file_lock);
}

// Edit file content on server
void edit_server_file(int client_fd, const char *filepath, const char *filename, const char *new_content, unsigned char *key, unsigned char *iv) {
    pthread_mutex_lock(&file_lock);

    // Open file for writing
    FILE *file = fopen(filepath, "w");
    if (!file) {
        char error_msg[BUFFER_SIZE];
        snprintf(error_msg, sizeof(error_msg), "Error: Could not open file '%s' for editing", filename);
        
        unsigned char buffer[BUFFER_SIZE], tag[16];
        int len = encrypt_gcm((unsigned char *)error_msg, strlen(error_msg), key, iv, buffer, tag);
        send_message(client_fd, buffer, len);
        send_message(client_fd, tag, 16);
        pthread_mutex_unlock(&file_lock);
        return;
    }

    // Write new content
    fputs(new_content, file);
    fclose(file);

    // Send success message
    char success_msg[BUFFER_SIZE];
    snprintf(success_msg, sizeof(success_msg), "File '%s' has been updated successfully", filename);
    
    unsigned char buffer[BUFFER_SIZE], tag[16];
    int len = encrypt_gcm((unsigned char *)success_msg, strlen(success_msg), key, iv, buffer, tag);
    send_message(client_fd, buffer, len);
    send_message(client_fd, tag, 16);
    pthread_mutex_unlock(&file_lock);
}

// Copy file on server
void copy_server_file(int client_fd, const char *filepath, const char *filename, unsigned char *key, unsigned char *iv) {
    pthread_mutex_lock(&file_lock);
    char new_filepath[BUFFER_SIZE];
    
    // Create the new filename with (copy).txt
    char *dot = strrchr(filename, '.');
    if (dot) {
        // If file has extension
        size_t name_len = dot - filename;
        char base_name[256];
        strncpy(base_name, filename, name_len);
        base_name[name_len] = '\0';
        snprintf(new_filepath, sizeof(new_filepath), "serverfiles/%s (copy).txt", base_name);
    } else {
        // If file has no extension
        snprintf(new_filepath, sizeof(new_filepath), "serverfiles/%s (copy).txt", filename);
    }

    // Open source file
    FILE *source = fopen(filepath, "r");
    if (!source) {
        char error_msg[BUFFER_SIZE];
        snprintf(error_msg, sizeof(error_msg), "Error: Could not open source file '%s'", filename);
        
        unsigned char buffer[BUFFER_SIZE], tag[16];
        int len = encrypt_gcm((unsigned char *)error_msg, strlen(error_msg), key, iv, buffer, tag);
        send_message(client_fd, buffer, len);
        send_message(client_fd, tag, 16);
        pthread_mutex_unlock(&file_lock);
        return;
    }

    // Open destination file
    FILE *dest = fopen(new_filepath, "w");
    if (!dest) {
        char error_msg[BUFFER_SIZE];
        snprintf(error_msg, sizeof(error_msg), "Error: Could not create copy file");
        
        unsigned char buffer[BUFFER_SIZE], tag[16];
        int len = encrypt_gcm((unsigned char *)error_msg, strlen(error_msg), key, iv, buffer, tag);
        send_message(client_fd, buffer, len);
        send_message(client_fd, tag, 16);
        fclose(source);
        pthread_mutex_unlock(&file_lock);
        return;
    }

    // Copy content
    char ch;
    while ((ch = fgetc(source)) != EOF) {
        fputc(ch, dest);
    }

    fclose(source);
    fclose(dest);

    // Send success message
    char success_msg[BUFFER_SIZE];
    snprintf(success_msg, sizeof(success_msg), "File copied successfully as '%s'", strrchr(new_filepath, '/') + 1);
    
    unsigned char buffer[BUFFER_SIZE], tag[16];
    int len = encrypt_gcm((unsigned char *)success_msg, strlen(success_msg), key, iv, buffer, tag);
    send_message(client_fd, buffer, len);
    send_message(client_fd, tag, 16);
    pthread_mutex_unlock(&file_lock);
}

// Read and send file content
void read_server_file_content(int client_fd, const char *filepath, const char *filename, unsigned char *key, unsigned char *iv) {
    pthread_mutex_lock(&file_lock);

    // Open and read the file
    FILE *file = fopen(filepath, "r");
    if (!file) {
        char error_msg[BUFFER_SIZE];
        snprintf(error_msg, sizeof(error_msg), "Error: Could not open file '%s'", filename);
        
        unsigned char buffer[BUFFER_SIZE], tag[16];
        int len = encrypt_gcm((unsigned char *)error_msg, strlen(error_msg), key, iv, buffer, tag);
        send_message(client_fd, buffer, len);
        send_message(client_fd, tag, 16);
        pthread_mutex_unlock(&file_lock);
        return;
    }

    // Read file content
    char content[BUFFER_SIZE] = {0};
    size_t bytes_read = fread(content, 1, sizeof(content) - 1, file);
    fclose(file);

    if (bytes_read == 0) {
        strcpy(content, "File is empty");
    } else {
        content[bytes_read] = '\0';
    }

    // Encrypt and send the content
    unsigned char buffer[BUFFER_SIZE], tag[16];
    int len = encrypt_gcm((unsigned char *)content, strlen(content), key, iv, buffer, tag);
    send_message(client_fd, buffer, len);
    send_message(client_fd, tag, 16);
    pthread_mutex_unlock(&file_lock);
}

// List files in directory
void list_files(int client_fd, const char *dirpath, unsigned char *key, unsigned char *iv) {
    pthread_mutex_lock(&file_lock);
    DIR *d;
    struct dirent *dir;
    unsigned char buffer[BUFFER_SIZE], tag[16];
    char files_list[BUFFER_SIZE] = "";

    d = opendir(dirpath);  // Open the directory
    if (d) {
        strcat(files_list, "Files in server:\n");

        while ((dir = readdir(d)) != NULL) {
            if (dir->d_type == DT_REG) {  // Only regular files
                strcat(files_list, "- ");
                strcat(files_list, dir->d_name);
                strcat(files_list, "\n");
            }
        }
        closedir(d);
    } else {
        strcpy(files_list, "Error: Could not open serverfiles directory.");
    }

    int len = encrypt_gcm((unsigned char *)files_list, strlen(files_list), key, iv, buffer, tag);
    send_message(client_fd, buffer, len);
    send_message(client_fd, tag, 16);
    pthread_mutex_unlock(&file_lock);
}

// Print log message in box
void print_log_boxed(const char *title, const char *log) {
    printf("\n==================== %s ====================\n\n", title);
    printf("%s", log);  
    printf("\n=======================================================\n");
}

// Check user permissions
bool check_permission(const char *role, char operation) {
    if (strcmp(role, "top") == 0) {
        return true;  // top role has all permissions
    }
    if (strcmp(role, "medium") == 0) {
        // medium can do everything except upload, download, delete, and rename
        return (operation != '5' && operation != '6' && operation != '7' && operation != '8');
    }
    // entry can only list and read
    return (operation == '1' || operation == '2');
}

// Send error message to client
void send_error(int client_fd, const char *error, unsigned char *key, unsigned char *iv) {
    unsigned char buffer[BUFFER_SIZE], tag[16];
    int len = encrypt_gcm((unsigned char *)error, strlen(error), key, iv, buffer, tag);
    send_message(client_fd, buffer, len);
    send_message(client_fd, tag, 16);
}

// Handle client connection and operations
void *handle_client(void *arg) {
    int *p = (int *)arg;      
    int client_fd = *p;       
    free(p);                   
    p = NULL;  

    int client_id;
    pthread_mutex_lock(&counter_lock);
    client_id = ++client_counter;
    pthread_mutex_unlock(&counter_lock);

    unsigned char key[32], iv[12], tag[16];
    unsigned char buffer[BUFFER_SIZE], dec_buf[BUFFER_SIZE];
    char username[50], password[50];
    int attempts = 0;
    const int maximum_attempts = 3;
    char log[BUFFER_SIZE * 4] = {0};
    char role[20] = {0};
    char log_main[BUFFER_SIZE * 2] = {0};
    char log_server_file[BUFFER_SIZE * 2] = {0};

    snprintf(log, sizeof(log), "\n\n======= New client connected: Client #%d =======\n", client_id);

    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    send(client_fd, key, 32, 0);
    send(client_fd, iv, 12, 0);

    while (attempts < maximum_attempts) {
        int len = read_message(client_fd, buffer, "received username");
        read_message(client_fd, tag, "received tag");
        print_hex(log, "Encrypted Username: ", buffer, len);
        decrypt_gcm(buffer, len, tag, key, iv, (unsigned char *)username);
        snprintf(log + strlen(log), sizeof(log) - strlen(log), "Decrypted Username: %s\n", username);

        len = read_message(client_fd, buffer, "received password");
        read_message(client_fd, tag, "received tag");
        print_hex(log, "Encrypted Password: ", buffer, len);
        decrypt_gcm(buffer, len, tag, key, iv, (unsigned char *)password);
        snprintf(log + strlen(log), sizeof(log) - strlen(log), "Decrypted Password: %s\n", password);

        if (authenticate(username, password, role)) {
            snprintf(log + strlen(log), sizeof(log) - strlen(log), "Authentication successful\n");
            len = encrypt_gcm((unsigned char *)"Authentication successful", 26, key, iv, buffer, tag);
            send_message(client_fd, buffer, len);
            send_message(client_fd, tag, 16);
            char auth_success[100];
            snprintf(auth_success, sizeof(auth_success), "Authentication successful\nYour role is: %s", role);
            len = encrypt_gcm((unsigned char *)auth_success, strlen(auth_success), key, iv, buffer, tag);
            send_message(client_fd, buffer, len);
            send_message(client_fd, tag, 16);

            while (1) {
                len = read_message(client_fd, buffer, "received choice");
                read_message(client_fd, tag, "received tag");
                decrypt_gcm(buffer, len, tag, key, iv, dec_buf);

                if (dec_buf[0] < '1' || dec_buf[0] > '4') {
                char error_msg[] = "Invalid menu choice. Please try again.";
                unsigned char buffer[BUFFER_SIZE], tag[16];
                int len = encrypt_gcm((unsigned char *)error_msg, strlen(error_msg), key, iv, buffer, tag);
                send_message(client_fd, buffer, len);
                send_message(client_fd, tag, 16);
                continue;
            }
            if (dec_buf[0] == '4') {
                    snprintf(log + strlen(log), sizeof(log) - strlen(log), "client Chose to exit\n");
                    break; // EXIT server connection
                }
                else if (dec_buf[0] == '1') {
                    // Send a message to server
                    snprintf(log + strlen(log), sizeof(log) - strlen(log), "Client chose: Send message to user\n");
                    const char *prompt = "Enter your message:";
                    len = encrypt_gcm((unsigned char *)prompt, strlen(prompt), key, iv, buffer, tag);
                    send_message(client_fd, buffer, len);
                    send_message(client_fd, tag, 16);
            
                    len = read_message(client_fd, buffer, "received message");
                    read_message(client_fd, tag, "received tag");
                    memset(dec_buf, 0, sizeof(dec_buf));
                    decrypt_gcm(buffer, len, tag, key, iv, dec_buf);
            
                    char temp[BUFFER_SIZE + 64];
                    snprintf(temp, sizeof(temp), "Message: %s\n", dec_buf);
                    strncat(log, temp, sizeof(log) - strlen(log) - 1);
            
                    const char *ack = "Message received.";
                    len = encrypt_gcm((unsigned char *)ack, strlen(ack), key, iv, buffer, tag);
                    send_message(client_fd, buffer, len);
                    send_message(client_fd, tag, 16);
                }
                else if (dec_buf[0] == '2') {
                    // Enter SERVER FILE submenu
                    snprintf(log + strlen(log), sizeof(log) - strlen(log), "Client chose: server files submenu\n");
                    while (1) {
                        memset(dec_buf, 0, sizeof(dec_buf));
                        len = read_message(client_fd, buffer, "server file menu choice");
                        read_message(client_fd, tag, "server file menu tag");
                        decrypt_gcm(buffer, len, tag, key, iv, dec_buf);
                        dec_buf[strcspn((char *)dec_buf, "\n")] = '\0';  // clean newline
            
                        if (dec_buf[0] < '1' || dec_buf[0] > '9') {
            char error_msg[] = "Invalid menu choice. Please try again.";
            unsigned char buffer[BUFFER_SIZE], tag[16];
            int len = encrypt_gcm((unsigned char *)error_msg, strlen(error_msg), key, iv, buffer, tag);
            send_message(client_fd, buffer, len);
            send_message(client_fd, tag, 16);
            continue;
        }
        if (dec_buf[0] == '9') {  // Back to main menu
                            snprintf(log + strlen(log), sizeof(log) - strlen(log), "Returned from server file menu\n");
                            break;
                        } else if (dec_buf[0] == '2') {  // Read file content
                            // Get filename from client
                            memset(buffer, 0, sizeof(buffer));
                            len = read_message(client_fd, buffer, "recv filename");
                            read_message(client_fd, tag, "recv filename tag");
                            
                            if (decrypt_gcm(buffer, len, tag, key, iv, dec_buf) < 0) {
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Failed to decrypt filename\n");
                                continue;
                            }
                            dec_buf[strcspn((char *)dec_buf, "\n")] = '\0';

                            // Read and send file content
                            char read_filepath[BUFFER_SIZE];
                            strcpy(read_filepath, "serverfiles/");
strncat(read_filepath, (char *)dec_buf, sizeof(read_filepath) - strlen(read_filepath) - 1);
                            read_server_file_content(client_fd, read_filepath, (char *)dec_buf, key, iv);
                            snprintf(log + strlen(log), sizeof(log) - strlen(log), "Read file: %s\n", dec_buf);
                        } else if (dec_buf[0] == '4') {  // Copy file
                            if (!check_permission(role, '4')) {
                                send_error(client_fd, "Access denied: Insufficient permissions", key, iv);
                                continue;
                            }
                            // Get filename from client
                            memset(buffer, 0, sizeof(buffer));
                            len = read_message(client_fd, buffer, "recv filename");
                            read_message(client_fd, tag, "recv filename tag");
                            
                            if (decrypt_gcm(buffer, len, tag, key, iv, dec_buf) < 0) {
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Failed to decrypt filename\n");
                                continue;
                            }
                            dec_buf[strcspn((char *)dec_buf, "\n")] = '\0';

                            // Copy the file
                            char copy_filepath[BUFFER_SIZE];
                            strcpy(copy_filepath, "serverfiles/");
strncat(copy_filepath, (char *)dec_buf, sizeof(copy_filepath) - strlen(copy_filepath) - 1);
                            copy_server_file(client_fd, copy_filepath, (char *)dec_buf, key, iv);
                            snprintf(log + strlen(log), sizeof(log) - strlen(log), "Copied file: %s\n", dec_buf);
                        } else if (dec_buf[0] == '3') {  // Edit file
                            if (!check_permission(role, '3')) {
                                send_error(client_fd, "Access denied: Insufficient permissions", key, iv);
                                continue;
                            }
                            // First get filename and show current content
                            memset(buffer, 0, sizeof(buffer));
                            len = read_message(client_fd, buffer, "recv filename");
                            read_message(client_fd, tag, "recv filename tag");
                            
                            if (decrypt_gcm(buffer, len, tag, key, iv, dec_buf) < 0) {
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Failed to decrypt filename\n");
                                continue;
                            }
                            dec_buf[strcspn((char *)dec_buf, "\n")] = '\0';

                            // Send current content
                            char read_filepath[BUFFER_SIZE];
                            strcpy(read_filepath, "serverfiles/");
strncat(read_filepath, (char *)dec_buf, sizeof(read_filepath) - strlen(read_filepath) - 1);
                            read_server_file_content(client_fd, read_filepath, (char *)dec_buf, key, iv);

                            // Get filename again for editing
                            memset(buffer, 0, sizeof(buffer));
                            len = read_message(client_fd, buffer, "recv filename");
                            read_message(client_fd, tag, "recv filename tag");
                            
                            if (decrypt_gcm(buffer, len, tag, key, iv, dec_buf) < 0) {
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Failed to decrypt filename\n");
                                continue;
                            }
                            dec_buf[strcspn((char *)dec_buf, "\n")] = '\0';
                            char filename[BUFFER_SIZE];
                            strcpy(filename, (char *)dec_buf);

                            // Get new content from client
                            memset(buffer, 0, sizeof(buffer));
                            len = read_message(client_fd, buffer, "recv content");
                            read_message(client_fd, tag, "recv content tag");
                            
                            if (decrypt_gcm(buffer, len, tag, key, iv, dec_buf) < 0) {
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Failed to decrypt content\n");
                                continue;
                            }
                            dec_buf[strcspn((char *)dec_buf, "\n")] = '\0';

                            // Edit the file
                            char edit_filepath[BUFFER_SIZE];
                            strcpy(edit_filepath, "serverfiles/");
strncat(edit_filepath, filename, sizeof(edit_filepath) - strlen(edit_filepath) - 1);
                            edit_server_file(client_fd, edit_filepath, filename, (char *)dec_buf, key, iv);
                            snprintf(log + strlen(log), sizeof(log) - strlen(log), "Edited file: %s\n", filename);
                        } else if (dec_buf[0] == '8') {  // Delete file
                            // Get filename from client
                            memset(buffer, 0, sizeof(buffer));
                            len = read_message(client_fd, buffer, "recv filename");
                            read_message(client_fd, tag, "recv filename tag");
                            
                            if (decrypt_gcm(buffer, len, tag, key, iv, dec_buf) < 0) {
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Failed to decrypt filename\n");
                                continue;
                            }
                            dec_buf[strcspn((char *)dec_buf, "\n")] = '\0';

                            // Delete the file
                            char delete_filepath[BUFFER_SIZE];
                            strcpy(delete_filepath, "serverfiles/");
strncat(delete_filepath, (char *)dec_buf, sizeof(delete_filepath) - strlen(delete_filepath) - 1);
                            delete_server_file(client_fd, delete_filepath, (char *)dec_buf, key, iv);
                            snprintf(log + strlen(log), sizeof(log) - strlen(log), "Deleted file: %s\n", dec_buf);
                        } else if (dec_buf[0] == '7') {  // Rename file
                            // Get source filename from client
                            memset(buffer, 0, sizeof(buffer));
                            len = read_message(client_fd, buffer, "recv source filename");
                            read_message(client_fd, tag, "recv source filename tag");
                            
                            if (decrypt_gcm(buffer, len, tag, key, iv, dec_buf) < 0) {
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Failed to decrypt source filename\n");
                                continue;
                            }
                            dec_buf[strcspn((char *)dec_buf, "\n")] = '\0';
                            char source_filename[BUFFER_SIZE];
                            strcpy(source_filename, (char *)dec_buf);

                            // Get destination filename from client
                            memset(buffer, 0, sizeof(buffer));
                            len = read_message(client_fd, buffer, "recv dest filename");
                            read_message(client_fd, tag, "recv dest filename tag");
                            
                            if (decrypt_gcm(buffer, len, tag, key, iv, dec_buf) < 0) {
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Failed to decrypt dest filename\n");
                                continue;
                            }
                            dec_buf[strcspn((char *)dec_buf, "\n")] = '\0';

                            // Rename the file
                            char old_path[BUFFER_SIZE], new_path[BUFFER_SIZE];
                            strcpy(old_path, "serverfiles/");
strncat(old_path, source_filename, sizeof(old_path) - strlen(old_path) - 1);
                            strcpy(new_path, "serverfiles/");
strncat(new_path, (char *)dec_buf, sizeof(new_path) - strlen(new_path) - 1);
                            rename_server_file(client_fd, old_path, new_path, source_filename, (char *)dec_buf, key, iv);
                            snprintf(log + strlen(log), sizeof(log) - strlen(log), "Renamed file from %s to %s\n", 
                                    source_filename, (char *)dec_buf);
                        } else if (dec_buf[0] == '5') {  // Upload file
                            if (!check_permission(role, '5')) { // Upload requires top permission
                                send_error(client_fd, "Access denied: Insufficient permissions", key, iv);
                                continue;
                            }
                            // Get filename from client
                            memset(buffer, 0, sizeof(buffer));
                            len = read_message(client_fd, buffer, "recv filename");
                            read_message(client_fd, tag, "recv filename tag");
                            
                            if (decrypt_gcm(buffer, len, tag, key, iv, dec_buf) < 0) {
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Failed to decrypt filename\n");
                                continue;
                            }
                            dec_buf[strcspn((char *)dec_buf, "\n")] = '\0';
                            char filename[BUFFER_SIZE];
                            strcpy(filename, (char *)dec_buf);

                            // Get file content from client
                            memset(buffer, 0, sizeof(buffer));
                            len = read_message(client_fd, buffer, "recv file content");
                            read_message(client_fd, tag, "recv content tag");
                            
                            if (decrypt_gcm(buffer, len, tag, key, iv, dec_buf) < 0) {
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Failed to decrypt file content\n");
                                continue;
                            }

                            // Handle the upload
                            char upload_filepath[BUFFER_SIZE];
                            strcpy(upload_filepath, "serverfiles/");
strncat(upload_filepath, filename, sizeof(upload_filepath) - strlen(upload_filepath) - 1);
                            handle_file_upload(client_fd, upload_filepath, filename, (char *)dec_buf, key, iv);
                            snprintf(log + strlen(log), sizeof(log) - strlen(log), "Uploaded file: %s\n", filename);
                        } else if (dec_buf[0] == '6') {  // Download file
                            if (!check_permission(role, '6')) { // Download requires top permission
                                send_error(client_fd, "Access denied: Insufficient permissions", key, iv);
                                continue;
                            }
                            // Get filename from client
                            memset(buffer, 0, sizeof(buffer));
                            len = read_message(client_fd, buffer, "recv filename");
                            read_message(client_fd, tag, "recv filename tag");
                            
                            if (decrypt_gcm(buffer, len, tag, key, iv, dec_buf) < 0) {
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Failed to decrypt filename\n");
                                continue;
                            }
                            dec_buf[strcspn((char *)dec_buf, "\n")] = '\0';

                            // Handle the download
                            char download_filepath[BUFFER_SIZE];
                            strcpy(download_filepath, "serverfiles/");
                            strncat(download_filepath, (char *)dec_buf, sizeof(download_filepath) - strlen(download_filepath) - 1);
                            handle_file_download(client_fd, download_filepath, (char *)dec_buf, key, iv);
                            snprintf(log + strlen(log), sizeof(log) - strlen(log), "Downloaded file: %s\n", (char *)dec_buf);
                        }
                        else if (dec_buf[0] == '1') {  // List server files
                            list_files(client_fd, "serverfiles", key, iv);
                        } else if (dec_buf[0] == '2') {  // Read file content
                            // Get filename from client
                            memset(buffer, 0, sizeof(buffer));
                            len = read_message(client_fd, buffer, "recv filename");
                            read_message(client_fd, tag, "recv filename tag");
                            
                            if (decrypt_gcm(buffer, len, tag, key, iv, dec_buf) < 0) {
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Failed to decrypt filename\n");
                                continue;
                            }
                            dec_buf[strcspn((char *)dec_buf, "\n")] = '\0';

                            // Read and send file content
                            char read_filepath[BUFFER_SIZE];
                            strcpy(read_filepath, "serverfiles/");
strncat(read_filepath, (char *)dec_buf, sizeof(read_filepath) - strlen(read_filepath) - 1);
                            read_server_file_content(client_fd, read_filepath, (char *)dec_buf, key, iv);
                            snprintf(log + strlen(log), sizeof(log) - strlen(log), "Read file: %s\n", dec_buf);
                        } else {
                            if (strlen((char *)dec_buf) == 0 || dec_buf[0] == ' ') {
                                const char *bad = "Invalid choice. Please enter a valid option.";
                                len = encrypt_gcm((unsigned char *)bad, strlen(bad), key, iv, buffer, tag);
                                send_message(client_fd, buffer, len);
                                send_message(client_fd, tag, 16);
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Empty input received. Resending menu...\n");
                            } else {
                                const char *bad = "Invalid server file menu choice.";
                                len = encrypt_gcm((unsigned char *)bad, strlen(bad), key, iv, buffer, tag);
                                send_message(client_fd, buffer, len);
                                send_message(client_fd, tag, 16);
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Invalid option received. Resending menu...\n");
                            }
                        }
                    }
                } else if (dec_buf[0] == '3') {
                    snprintf(log + strlen(log), sizeof(log) - strlen(log), "Client chose: Client File Menu\n");
                    // Enter CLIENT FILE submenu
                    while (1) {
                        memset(dec_buf, 0, sizeof(dec_buf));
                        len = read_message(client_fd, buffer, "client file menu choice");
                        read_message(client_fd, tag, "client file menu tag");
                        decrypt_gcm(buffer, len, tag, key, iv, dec_buf);
                        dec_buf[strcspn((char *)dec_buf, "\n")] = '\0';  // clean newline
            
                        if (dec_buf[0] < '1' || dec_buf[0] > '9') {
            char error_msg[] = "Invalid menu choice. Please try again.";
            unsigned char buffer[BUFFER_SIZE], tag[16];
            int len = encrypt_gcm((unsigned char *)error_msg, strlen(error_msg), key, iv, buffer, tag);
            send_message(client_fd, buffer, len);
            send_message(client_fd, tag, 16);
            continue;
        }
        if (dec_buf[0] == '9') {  // Back to main menu
                            snprintf(log + strlen(log), sizeof(log) - strlen(log), "Returned from client file menu\n");
                            break;
                        }
                        else if (dec_buf[0] == '1') {  // List client files
                            list_files(client_fd, "../clientt/clientfiles", key, iv);
                            snprintf(log + strlen(log), sizeof(log) - strlen(log), "Listed client files\n");
                        } else if (dec_buf[0] == '2') {  // Read client file
                            // Get filename from client
                            memset(buffer, 0, sizeof(buffer));
                            len = read_message(client_fd, buffer, "recv filename");
                            read_message(client_fd, tag, "recv filename tag");
                            
                            if (decrypt_gcm(buffer, len, tag, key, iv, dec_buf) < 0) {
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Failed to decrypt filename\n");
                                continue;
                            }
                            dec_buf[strcspn((char *)dec_buf, "\n")] = '\0';

                            // Read and send file content
                            char read_filepath[BUFFER_SIZE];
                            strcpy(read_filepath, "../clientt/clientfiles/");
strncat(read_filepath, (char *)dec_buf, sizeof(read_filepath) - strlen(read_filepath) - 1);
                            read_server_file_content(client_fd, read_filepath, (char *)dec_buf, key, iv);
                            snprintf(log + strlen(log), sizeof(log) - strlen(log), "Read client file: %s\n", dec_buf);
                        } else if (dec_buf[0] == '3') {  // Edit client file
                            memset(buffer, 0, sizeof(buffer));
                            len = read_message(client_fd, buffer, "recv filename");
                            read_message(client_fd, tag, "recv filename tag");
                             
                            if (decrypt_gcm(buffer, len, tag, key, iv, dec_buf) < 0) {
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Failed to decrypt filename\n");
                                continue;
                            }
                            dec_buf[strcspn((char *)dec_buf, "\n")] = '\0';

                            // Send current content
                            char read_filepath[BUFFER_SIZE];
                            strcpy(read_filepath, "../clientt/clientfiles/");
strncat(read_filepath, (char *)dec_buf, sizeof(read_filepath) - strlen(read_filepath) - 1);
                            read_server_file_content(client_fd, read_filepath, (char *)dec_buf, key, iv);

                            // Get filename again for editing
                            memset(buffer, 0, sizeof(buffer));
                            len = read_message(client_fd, buffer, "recv filename");
                            read_message(client_fd, tag, "recv filename tag");
                             
                            if (decrypt_gcm(buffer, len, tag, key, iv, dec_buf) < 0) {
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Failed to decrypt filename\n");
                                continue;
                            }
                            dec_buf[strcspn((char *)dec_buf, "\n")] = '\0';
                            char filename[BUFFER_SIZE];
                            strcpy(filename, (char *)dec_buf);

                            // Get new content from client
                            memset(buffer, 0, sizeof(buffer));
                            len = read_message(client_fd, buffer, "recv content");
                            read_message(client_fd, tag, "recv content tag");
                             
                            if (decrypt_gcm(buffer, len, tag, key, iv, dec_buf) < 0) {
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Failed to decrypt content\n");
                                continue;
                            }
                            dec_buf[strcspn((char *)dec_buf, "\n")] = '\0';

                            // Edit the file
                            char edit_filepath[BUFFER_SIZE];
                            strcpy(edit_filepath, "../clientt/clientfiles/");
                            strncat(edit_filepath, filename, sizeof(edit_filepath) - strlen(edit_filepath) - 1);
                            edit_server_file(client_fd, edit_filepath, filename, (char *)dec_buf, key, iv);
                            snprintf(log + strlen(log), sizeof(log) - strlen(log), "Edited client file: %s\n", filename);
                        } else if (dec_buf[0] == '4') {  // Copy client file
                            // Get filename from client
                            memset(buffer, 0, sizeof(buffer));
                            len = read_message(client_fd, buffer, "recv filename");
                            read_message(client_fd, tag, "recv filename tag");
                            
                            if (decrypt_gcm(buffer, len, tag, key, iv, dec_buf) < 0) {
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Failed to decrypt filename\n");
                                continue;
                            }
                            dec_buf[strcspn((char *)dec_buf, "\n")] = '\0';

                            // Copy the file
                            char copy_filepath[BUFFER_SIZE];
                            strcpy(copy_filepath, "../clientt/clientfiles/");
                            strncat(copy_filepath, (char *)dec_buf, sizeof(copy_filepath) - strlen(copy_filepath) - 1);
                            copy_server_file(client_fd, copy_filepath, (char *)dec_buf, key, iv);
                            snprintf(log + strlen(log), sizeof(log) - strlen(log), "Copied client file: %s\n", dec_buf);
                        } else if (dec_buf[0] == '7') {  // Rename file
                            // Get source filename from client
                            memset(buffer, 0, sizeof(buffer));
                            len = read_message(client_fd, buffer, "recv source filename");
                            read_message(client_fd, tag, "recv source filename tag");
                            
                            if (decrypt_gcm(buffer, len, tag, key, iv, dec_buf) < 0) {
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Failed to decrypt source filename\n");
                                continue;
                            }
                            char source_filename[BUFFER_SIZE];
                            strncpy(source_filename, (char *)dec_buf, sizeof(source_filename));
                            source_filename[strcspn(source_filename, "\n")] = '\0';

                            // Get destination filename
                            memset(buffer, 0, sizeof(buffer));
                            len = read_message(client_fd, buffer, "recv dest filename");
                            read_message(client_fd, tag, "recv dest filename tag");
                            
                            if (decrypt_gcm(buffer, len, tag, key, iv, dec_buf) < 0) {
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Failed to decrypt dest filename\n");
                                continue;
                            }
                            dec_buf[strcspn((char *)dec_buf, "\n")] = '\0';

                            // Rename the file
                            char old_path[BUFFER_SIZE], new_path[BUFFER_SIZE];
                            strcpy(old_path, "../clientt/clientfiles/");
                            strncat(old_path, source_filename, sizeof(old_path) - strlen(old_path) - 1);
                            strcpy(new_path, "../clientt/clientfiles/");
                            strncat(new_path, (char *)dec_buf, sizeof(new_path) - strlen(new_path) - 1);
                            rename_server_file(client_fd, old_path, new_path, source_filename, (char *)dec_buf, key, iv);
                            snprintf(log + strlen(log), sizeof(log) - strlen(log), "Renamed client file from %s to %s\n", source_filename, (char *)dec_buf);
                        } else if (dec_buf[0] == '6') {  // Delete file
                            // Get filename from client
                            memset(buffer, 0, sizeof(buffer));
                            len = read_message(client_fd, buffer, "recv filename");
                            read_message(client_fd, tag, "recv filename tag");
                            
                            if (decrypt_gcm(buffer, len, tag, key, iv, dec_buf) < 0) {
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Failed to decrypt filename\n");
                                continue;
                            }
                            dec_buf[strcspn((char *)dec_buf, "\n")] = '\0';

                            // Delete the file
                            char delete_filepath[BUFFER_SIZE];
                            strcpy(delete_filepath, "../clientt/clientfiles/");
                            strncat(delete_filepath, (char *)dec_buf, sizeof(delete_filepath) - strlen(delete_filepath) - 1);
                            delete_server_file(client_fd, delete_filepath, (char *)dec_buf, key, iv);
                            snprintf(log + strlen(log), sizeof(log) - strlen(log), "Deleted client file: %s\n", dec_buf);
                        } else {
                            if (strlen((char *)dec_buf) == 0 || dec_buf[0] == ' ') {
                                const char *bad = "Invalid choice. Please enter a valid option.";
                                len = encrypt_gcm((unsigned char *)bad, strlen(bad), key, iv, buffer, tag);
                                send_message(client_fd, buffer, len);
                                send_message(client_fd, tag, 16);
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Empty input received. Resending menu...\n");
                            } else {
                                const char *bad = "Invalid client file menu choice.";
                                len = encrypt_gcm((unsigned char *)bad, strlen(bad), key, iv, buffer, tag);
                                send_message(client_fd, buffer, len);
                                send_message(client_fd, tag, 16);
                                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Invalid option received. Resending menu...\n");
                            }
                        }
                    }
                } else if (dec_buf[0] == '5') {
                    snprintf(log + strlen(log), sizeof(log) - strlen(log), "Client chose to exit\n");
                    break;
                } else {
                    if (strlen((char *)dec_buf) == 0 || dec_buf[0] == ' ') {
                        const char *bad = "Invalid choice. Please enter a valid option.";
                        len = encrypt_gcm((unsigned char *)bad, strlen(bad), key, iv, buffer, tag);
                        send_message(client_fd, buffer, len);
                        send_message(client_fd, tag, 16);
                        snprintf(log + strlen(log), sizeof(log) - strlen(log), "Empty input received. Resending menu...\n");
                    } else {
                        const char *bad = "Invalid choice. Please try again.";
                        len = encrypt_gcm((unsigned char *)bad, strlen(bad), key, iv, buffer, tag);
                        send_message(client_fd, buffer, len);
                        send_message(client_fd, tag, 16);
                        snprintf(log + strlen(log), sizeof(log) - strlen(log), "Invalid option received. Resending menu...\n");
                    }
                    continue;
                }
            }
            break;
        } else {
            attempts++;
            snprintf(log + strlen(log), sizeof(log) - strlen(log), "Authentication failed - attempt %d\n", attempts);
            if (attempts == maximum_attempts) {
                len = encrypt_gcm((unsigned char *)"Authentication failed. Too many attempts.", 44, key, iv, buffer, tag);
                send_message(client_fd, buffer, len);
                send_message(client_fd, tag, 16);
                snprintf(log + strlen(log), sizeof(log) - strlen(log), "Disconnected after max attempts\n");
                break;
            } else {
                len = encrypt_gcm((unsigned char *)"Authentication failed. Try again.", 36, key, iv, buffer, tag);
                send_message(client_fd, buffer, len);
                send_message(client_fd, tag, 16);
                sleep(1);
            }
        }
    }

    pthread_mutex_lock(&counter_lock);
    printf("%s", log);
    pthread_mutex_unlock(&counter_lock);

    close(client_fd);
    return NULL;
}

// Main server function
int main() {
    int server_fd;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);

    pthread_mutex_init(&counter_lock, NULL);
    pthread_mutex_init(&file_lock, NULL);

    printf("\n=== Secure Server with Multithreading Started ===\n");

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, MAX_CLIENTS);

    printf("Listening on port %d...\n", PORT);

    while (1) {
        int *client_fd = malloc(sizeof(int));
        if (client_fd == NULL) {
            perror("Memory allocation failed");
            continue;
        }
        *client_fd = accept(server_fd, (struct sockaddr *)&address, &addrlen);
        if (*client_fd < 0) {
            perror("Accept failed");
            free(client_fd);
            continue;
        }

        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, client_fd);
        pthread_detach(tid);
    }

    pthread_mutex_destroy(&counter_lock);
    pthread_mutex_destroy(&file_lock);
    close(server_fd);
    return 0;
}
