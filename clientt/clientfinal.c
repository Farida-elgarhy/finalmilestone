#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// Remove newline from string
void remove_newline(char *str) {
    for (int i = 0; str[i]; i++) {
        if (str[i] == '\n') {
            str[i] = '\0';
            break;
        }
    }
}

// Send message to socket
void send_message(int sock, unsigned char *data, int len, const char *error_msg) {
    uint32_t net_len = htonl(len);
    if (send(sock, &net_len, sizeof(net_len), 0) < 0 ||
        send(sock, data, len, 0) < 0) {
        perror(error_msg);
        close(sock);
        exit(EXIT_FAILURE);
    }
}

// Read message from socket
int read_message(int sock, unsigned char *buf, const char *err_msg) {
    uint32_t net_len;
    if (recv(sock, &net_len, sizeof(net_len), MSG_WAITALL) <= 0) {
        perror("Length read failed");
        close(sock);
        exit(EXIT_FAILURE);
    }
    int len = ntohl(net_len);
    if (recv(sock, buf, len, MSG_WAITALL) <= 0) {
        perror(err_msg);
        close(sock);
        exit(EXIT_FAILURE);
    }
    return len;
}

// Print data as hex
void strToHex(const char *label, unsigned char *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) printf("%02X", data[i]);
    printf("\n");
}
//encrypt using aes gcm
int encrypt_gcm(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv,
                unsigned char *enc_buf, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, enc_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, enc_buf, &len, plaintext, plaintext_len);
    enc_len = len;

    EVP_EncryptFinal_ex(ctx, enc_buf + len, &len);
    enc_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    return enc_len;
}

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

// Display main menu options
void show_main_menu() {
    printf("\n====================== Main Menu ======================\n\n");
    printf("1. Send a message to the server\n");
    printf("2. Server files options\n");
    printf("3. Client files options\n");
    printf("4. Exit\n");
    printf("\n=======================================================\n");
    printf("Enter your choice: ");
}
// Print content in a box with title
void print_boxed(const char *title, const char *content) {
    printf("\n=================== %s ===================\n\n", title);
    printf("%s\n", content);
    printf("=========================================================\n");
}
// Display server file operations menu
void show_server_file_menu(const char *role, int sock, unsigned char *key, unsigned char *iv) {
    unsigned char buffer[BUFFER_SIZE], enc_buf[BUFFER_SIZE], tag[16];
    unsigned char dec_buf[BUFFER_SIZE];
    char choice[8];
    int enc_len;

    while (1) {
        printf("\n================== Server File Menu ===================\n\n");
        if (strcmp(role, "entry") == 0) {
            printf("1. List server files\n");
            printf("2. Read server file content\n");
        } else if (strcmp(role, "medium") == 0) {
            printf("1. List server files\n");
            printf("2. Read server file content\n");
            printf("3. Edit server file\n");
            printf("4. Copy server file\n");
        } else if (strcmp(role, "top") == 0) {
            printf("1. List server files\n");
            printf("2. Read server file content\n");
            printf("3. Edit server file\n");
            printf("4. Copy server file\n");
            printf("5. Upload file to server\n");
            printf("6. Download file from server\n");
            printf("7. Rename file\n");
            printf("8. Delete server file\n");
        }

        printf("9. Back to Main Menu\n");
        printf("\n=======================================================\n");
        printf("Enter your choice: ");

        fgets(choice, sizeof(choice), stdin);
        remove_newline(choice);

        // Send encrypted choice to server
        enc_len = encrypt_gcm((unsigned char *)choice, strlen(choice), key, iv, enc_buf, tag);
        send_message(sock, enc_buf, enc_len, "send server file choice");
        send_message(sock, tag, 16, "send tag");

        if (choice[0] == '9') break;
        if (choice[0] == '1') {
            // List server files
            enc_len = read_message(sock, buffer, "server file response");
            read_message(sock, tag, "server file tag");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
            print_boxed("Server Files", (char *)dec_buf);

        } else if (choice[0] == '2') {
            // Read server file content
            print_boxed("Server File Content", "Enter filename to read:");
            
            // Get filename from user
            char filename[50];
            fgets(filename, sizeof(filename), stdin);
            remove_newline(filename);
            
            // Send encrypted filename to server
            enc_len = encrypt_gcm((unsigned char *)filename, strlen(filename), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send filename");
            send_message(sock, tag, 16, "send filename tag");

            // Receive server reply
            enc_len = read_message(sock, buffer, "recv file response");
            read_message(sock, tag, "recv tag response");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);

            // Check if server replied with error or file content
            if (strncmp((char *)dec_buf, "Error:", 6) == 0) {
                // It's an error
                print_boxed("Error", (char *)dec_buf);
            } else {
                // It's the actual file content
                print_boxed("Server File Content", (char *)dec_buf);
            }

        } else if (choice[0] == '4') {
            // Copy server file
            print_boxed("Copy Server File", "Enter filename to copy:");
            
            // Get filename from user
            char filename[50];
            fgets(filename, sizeof(filename), stdin);
            remove_newline(filename);
            
            // Send encrypted filename to server
            enc_len = encrypt_gcm((unsigned char *)filename, strlen(filename), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send filename");
            send_message(sock, tag, 16, "send filename tag");

            // Receive server reply
            enc_len = read_message(sock, buffer, "recv copy response");
            read_message(sock, tag, "recv tag response");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);

            // Display the result
            print_boxed("Copy Result", (char *)dec_buf);

        } else if (choice[0] == '3') {
            // Edit server file
            print_boxed("Edit Server File", "Enter filename to edit:");
            
            // Get filename from user
            char filename[50];
            fgets(filename, sizeof(filename), stdin);
            remove_newline(filename);
            
            // First, read the current content
            enc_len = encrypt_gcm((unsigned char *)filename, strlen(filename), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send filename for read");
            send_message(sock, tag, 16, "send filename tag");

            // Receive current content
            enc_len = read_message(sock, buffer, "recv current content");
            read_message(sock, tag, "recv current content tag");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);

            // Display current content
            print_boxed("Current File Content", (char *)dec_buf);

            // Now send filename again for editing
            enc_len = encrypt_gcm((unsigned char *)filename, strlen(filename), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send filename");
            send_message(sock, tag, 16, "send filename tag");

            // Get new content from user
            print_boxed("Edit Content", "Enter new content:");
            
            char content[BUFFER_SIZE] = {0};
            char line[256];
            int content_len = 0;
            
            while (fgets(line, sizeof(line), stdin) != NULL) {
                if (line[0] == '\n') break;  // Empty line (double Enter) to finish
                strcat(content, line);
                content_len += strlen(line);
                if (content_len >= BUFFER_SIZE - 256) break;  // Safety check
            }

            // Send encrypted content to server
            enc_len = encrypt_gcm((unsigned char *)content, strlen(content), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send content");
            send_message(sock, tag, 16, "send content tag");

            // Receive server reply
            enc_len = read_message(sock, buffer, "recv edit response");
            read_message(sock, tag, "recv tag response");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);

            // Display the result
            print_boxed("Edit Result", (char *)dec_buf);

        } else if (choice[0] == '8') {
            // Delete server file
            print_boxed("Delete Server File", "Enter filename to delete:");
            
            // Get filename from user
            char filename[50];
            fgets(filename, sizeof(filename), stdin);
            remove_newline(filename);
            
            // Send encrypted filename to server
            enc_len = encrypt_gcm((unsigned char *)filename, strlen(filename), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send filename");
            send_message(sock, tag, 16, "send filename tag");

            // Receive server reply
            enc_len = read_message(sock, buffer, "recv delete response");
            read_message(sock, tag, "recv tag response");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);

            // Display the result
            print_boxed("Delete Result", (char *)dec_buf);

        } else if (choice[0] == '5') {
            // Upload file to server
            print_boxed("Upload File", "Enter filename from clientfiles folder:");
            
            // Get filename from user
            char filename[50];
            fgets(filename, sizeof(filename), stdin);
            remove_newline(filename);

            // Build the full path
            char filepath[BUFFER_SIZE];
            snprintf(filepath, sizeof(filepath), "clientfiles/%s", filename);

            // Try to open and read the file
            FILE *file = fopen(filepath, "r");
            if (!file) {
                print_boxed("Upload Error", "Could not open file for reading");
                continue;
            }

            // Read file content
            char content[BUFFER_SIZE];
            size_t bytes_read = fread(content, 1, sizeof(content) - 1, file);
            content[bytes_read] = '\0';
            fclose(file);

            // Send encrypted filename to server
            enc_len = encrypt_gcm((unsigned char *)filename, strlen(filename), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send filename");
            send_message(sock, tag, 16, "send filename tag");

            // Send encrypted file content to server
            enc_len = encrypt_gcm((unsigned char *)content, strlen(content), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send file content");
            send_message(sock, tag, 16, "send content tag");

            // Receive server reply
            enc_len = read_message(sock, buffer, "recv upload response");
            read_message(sock, tag, "recv tag response");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);

            // Display the result
            print_boxed("Upload Result", (char *)dec_buf);

        } else if (choice[0] == '6') {
            // Download file from server
            print_boxed("Download File", "Enter filename to download from server:");
            
            // Get filename from user
            char filename[50];
            fgets(filename, sizeof(filename), stdin);
            remove_newline(filename);

            // Send encrypted filename to server
            enc_len = encrypt_gcm((unsigned char *)filename, strlen(filename), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send filename");
            send_message(sock, tag, 16, "send filename tag");

            // Receive server response
            enc_len = read_message(sock, buffer, "recv download response");
            read_message(sock, tag, "recv tag response");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);

            // Check if download was successful
            if (strcmp((char *)dec_buf, "SUCCESS") == 0) {
                // Receive file content
                enc_len = read_message(sock, buffer, "recv file content");
                read_message(sock, tag, "recv content tag");
                decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);

                // Create the file in clientfiles
                char filepath[BUFFER_SIZE];
                snprintf(filepath, sizeof(filepath), "clientfiles/%s", filename);
                FILE *file = fopen(filepath, "w");

                if (!file) {
                    print_boxed("Download Error", "Could not create file in clientfiles folder");
                    continue;
                }

                // Write the decrypted content
                fputs((char *)dec_buf, file);
                fclose(file);

                print_boxed("Download Success", "File has been downloaded successfully");
            } else {
                // Display the error message from server
                print_boxed("Download Error", (char *)dec_buf);
            }

        } else if (choice[0] == '7') {
            // Rename server file
            print_boxed("Rename Server File", "Enter current filename:");
            
            // Get source filename from user
            char source_filename[50];
            fgets(source_filename, sizeof(source_filename), stdin);
            remove_newline(source_filename);
            
            // Send encrypted source filename to server
            enc_len = encrypt_gcm((unsigned char *)source_filename, strlen(source_filename), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send source filename");
            send_message(sock, tag, 16, "send source filename tag");

            // Get destination filename
            print_boxed("Rename Server File", "Enter new filename:");
            char dest_filename[50];
            fgets(dest_filename, sizeof(dest_filename), stdin);
            remove_newline(dest_filename);

            // Send encrypted destination filename to server
            enc_len = encrypt_gcm((unsigned char *)dest_filename, strlen(dest_filename), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send dest filename");
            send_message(sock, tag, 16, "send dest filename tag");

            // Receive server reply
            enc_len = read_message(sock, buffer, "recv rename response");
            read_message(sock, tag, "recv tag response");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);

            // Display the result
            print_boxed("Rename Result", (char *)dec_buf);

        } else {
            // Other choices (edit/copy/upload...) or invalids
            enc_len = read_message(sock, buffer, "server file response");
            read_message(sock, tag, "server file tag");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
            printf("Server: %s\n", dec_buf);
        }

    }
}

// Display client file operations menu
void show_client_file_menu(const char *role, int sock, unsigned char *key, unsigned char *iv) {
    unsigned char buffer[BUFFER_SIZE], enc_buf[BUFFER_SIZE], tag[16];
    unsigned char dec_buf[BUFFER_SIZE];
    char choice[8];
    int enc_len;

    while (1) {
        printf("\n================== Client File Menu ===================\n");
        printf("1. List client files\n");
        printf("2. Read client file content\n");

        if (strcmp(role, "medium") == 0 || strcmp(role, "top") == 0) {
            printf("3. Edit client file\n");
            printf("4. Copy client file\n");
        }

        if (strcmp(role, "top") == 0) {
            printf("5. Rename file\n");
            printf("6. Delete client file\n");
        }

        printf("9. Back to Main Menu\n");
        printf("\n=======================================================\n");
        printf("Enter your choice: ");

        fgets(choice, sizeof(choice), stdin);
        remove_newline(choice);

        // Check for empty input
        if (strlen(choice) == 0) {
            printf("Empty input. Please enter a valid choice.\n");
            continue;
        }

        // Send encrypted choice to server
        enc_len = encrypt_gcm((unsigned char *)choice, strlen(choice), key, iv, enc_buf, tag);
        send_message(sock, enc_buf, enc_len, "send client file choice");
        send_message(sock, tag, 16, "send tag");

        if (choice[0] == '9') break;

        // Handle client file operations based on choice
        if (choice[0] == '1') {  // List files
            // Receive and display file list
            enc_len = read_message(sock, buffer, "file list");
            read_message(sock, tag, "file list tag");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
            print_boxed("Client Files", (char *)dec_buf);
        } else if (choice[0] == '2') {  // Read file content
            print_boxed("Read Client File", "Enter filename to read:");

            char filename[BUFFER_SIZE];
            fgets(filename, sizeof(filename), stdin);
            remove_newline(filename);

            // Send filename
            enc_len = encrypt_gcm((unsigned char *)filename, strlen(filename), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send filename");
            send_message(sock, tag, 16, "send tag");

            // Receive and display file content
            enc_len = read_message(sock, buffer, "file content");
            read_message(sock, tag, "file content tag");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
            print_boxed("Server File Content", (char *)dec_buf);
        } else if (choice[0] == '3') {  // Edit file
            print_boxed("Edit Client File", "Enter filename to edit:");
            
            // Get filename from user
            char filename[50];
            fgets(filename, sizeof(filename), stdin);
            remove_newline(filename);
            
            // First, read the current content
            enc_len = encrypt_gcm((unsigned char *)filename, strlen(filename), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send filename for read");
            send_message(sock, tag, 16, "send filename tag");

            // Receive current content
            enc_len = read_message(sock, buffer, "recv current content");
            read_message(sock, tag, "recv current content tag");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);

            // Display current content
            print_boxed("Current File Content", (char *)dec_buf);

            // Now send filename again for editing
            enc_len = encrypt_gcm((unsigned char *)filename, strlen(filename), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send filename");
            send_message(sock, tag, 16, "send filename tag");

            // Get new content from user
            print_boxed("Edit Content", "Enter new content:");
            
            char content[BUFFER_SIZE] = {0};
            char line[256];
            int content_len = 0;
            
            while (fgets(line, sizeof(line), stdin) != NULL) {
                if (line[0] == '\n') break;  // Empty line (double Enter) to finish
                strcat(content, line);
                content_len += strlen(line);
                if (content_len >= BUFFER_SIZE - 256) break;  // Safety check
            }

            // Send encrypted content to server
            enc_len = encrypt_gcm((unsigned char *)content, strlen(content), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send content");
            send_message(sock, tag, 16, "send content tag");

            // Receive server reply
            enc_len = read_message(sock, buffer, "recv edit response");
            read_message(sock, tag, "recv tag response");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);

            // Display the result
            print_boxed("Edit Result", (char *)dec_buf);
        } else if (choice[0] == '4') {  // Copy file
            print_boxed("Copy Server File", "");
            printf("\nEnter filename to copy:\n");
            print_boxed("", "");

            char filename[BUFFER_SIZE];
            fgets(filename, sizeof(filename), stdin);
            remove_newline(filename);

            // Send filename
            enc_len = encrypt_gcm((unsigned char *)filename, strlen(filename), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send filename");
            send_message(sock, tag, 16, "send tag");

            // Receive copy result
            enc_len = read_message(sock, buffer, "copy result");
            read_message(sock, tag, "copy result tag");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
            print_boxed("Copy Result", (char *)dec_buf);
        } else if (choice[0] == '5') {  // Upload file
            print_boxed("Upload File", "");
            printf("\nEnter filename:\n");
            print_boxed("", "");

            char filename[BUFFER_SIZE];
            fgets(filename, sizeof(filename), stdin);
            remove_newline(filename);

            // Send filename
            enc_len = encrypt_gcm((unsigned char *)filename, strlen(filename), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send filename");
            send_message(sock, tag, 16, "send tag");

            print_boxed("File Content", "");
            printf("\nEnter file content (press Enter twice when done):\n");
            print_boxed("", "");

            char content[BUFFER_SIZE * 4] = "";
            char line[BUFFER_SIZE];
            while (fgets(line, sizeof(line), stdin)) {
                if (line[0] == '\n') break;
                strcat(content, line);
            }

            // Send content
            enc_len = encrypt_gcm((unsigned char *)content, strlen(content), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send content");
            send_message(sock, tag, 16, "send tag");

            // Receive upload result
            enc_len = read_message(sock, buffer, "upload result");
            read_message(sock, tag, "upload result tag");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
            print_boxed("Upload Result", (char *)dec_buf);
        } else if (choice[0] == '6') {  // Download file
            print_boxed("Download File", "Enter filename to download from server:");
            
            // Get filename from user
            char filename[50];
            fgets(filename, sizeof(filename), stdin);
            remove_newline(filename);
            
            // Send encrypted filename to server
            enc_len = encrypt_gcm((unsigned char *)filename, strlen(filename), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send filename");
            send_message(sock, tag, 16, "send filename tag");

            // Receive server response
            enc_len = read_message(sock, buffer, "recv download response");
            read_message(sock, tag, "recv tag response");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);

            if (strcmp((char *)dec_buf, "SUCCESS") == 0) {
                // If successful, receive and save the file content
                enc_len = read_message(sock, buffer, "recv file content");
                read_message(sock, tag, "recv content tag");
                decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
                
                // Save to file
                char save_path[BUFFER_SIZE];
                snprintf(save_path, sizeof(save_path), "clientfiles/%s", filename);
                FILE *file = fopen(save_path, "w");
                if (file) {
                    fprintf(file, "%s", (char *)dec_buf);
                    fclose(file);
                    print_boxed("Download Result", "File downloaded successfully");
                } else {
                    print_boxed("Download Error", "Could not save file locally");
                }
            } else {
                print_boxed("Download Error", (char *)dec_buf);
            }
        } else if (choice[0] == '7') {  // Move/Rename file
            print_boxed("Rename File", "Enter current filename:");

            char source_filename[BUFFER_SIZE];
            fgets(source_filename, sizeof(source_filename), stdin);
            remove_newline(source_filename);

            // Send source filename
            enc_len = encrypt_gcm((unsigned char *)source_filename, strlen(source_filename), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send source filename");
            send_message(sock, tag, 16, "send tag");

            print_boxed("Rename File", "Enter new filename:");

            char dest_filename[BUFFER_SIZE];
            fgets(dest_filename, sizeof(dest_filename), stdin);
            remove_newline(dest_filename);

            // Send destination filename
            enc_len = encrypt_gcm((unsigned char *)dest_filename, strlen(dest_filename), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send dest filename");
            send_message(sock, tag, 16, "send tag");

            // Receive rename result
            enc_len = read_message(sock, buffer, "rename result");
            read_message(sock, tag, "rename result tag");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
            print_boxed("Rename Result", (char *)dec_buf);
        } else if (choice[0] == '8') {  // Delete file
            print_boxed("Delete File", "Enter filename to delete:");

            char filename[BUFFER_SIZE];
            fgets(filename, sizeof(filename), stdin);
            remove_newline(filename);

            // Send filename
            enc_len = encrypt_gcm((unsigned char *)filename, strlen(filename), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send filename");
            send_message(sock, tag, 16, "send tag");

            // Receive delete result
            enc_len = read_message(sock, buffer, "delete result");
            read_message(sock, tag, "delete result tag");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
            print_boxed("Delete Result", (char *)dec_buf);
        } else {
            // Receive error message
            enc_len = read_message(sock, buffer, "error response");
            read_message(sock, tag, "error tag");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
            printf("Server: %s\n", dec_buf);
        }
    }
}

// Main client function
int main() {
    int sock;
    struct sockaddr_in server_address;
    char username[50], password[50];
    unsigned char key[32], iv[12];
    unsigned char buffer[BUFFER_SIZE], enc_buf[BUFFER_SIZE], dec_buf[BUFFER_SIZE];
    unsigned char tag[16];
    int enc_len;
    char choice[8];
    char role[20];

    const char *success_msg = "Authentication successful";
    const char *fail_msg = "Authentication failed. Too many attempts.";

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = INADDR_ANY;

    if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("Connection failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("\n=== Secure Client Started ===\n\n");

    if (read(sock, key, 32) != 32 || read(sock, iv, 12) != 12) {
        perror("Failed to receive key/IV");
        close(sock);
        exit(EXIT_FAILURE);
    }
    printf("Received encryption key and IV from server\n");

    while (1) {
        printf("Enter username: ");
        fgets(username, sizeof(username), stdin);
        remove_newline(username);
        enc_len = encrypt_gcm((unsigned char *)username, strlen(username), key, iv, enc_buf, tag);
        send_message(sock, enc_buf, enc_len, "send username");
        send_message(sock, tag, 16, "send tag username");

        printf("Enter password: ");
        fgets(password, sizeof(password), stdin);
        remove_newline(password);
        enc_len = encrypt_gcm((unsigned char *)password, strlen(password), key, iv, enc_buf, tag);
        send_message(sock, enc_buf, enc_len, "send password");
        send_message(sock, tag, 16, "send tag password");

        enc_len = read_message(sock, buffer, "recv auth result");
        read_message(sock, tag, "recv tag auth");
        decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);

        print_boxed("Server", (char *)dec_buf);

        if (strncmp((char *)dec_buf, "Authentication successful", 24) == 0) {
            // Receive and decrypt the role
            enc_len = read_message(sock, buffer, "recv role");
            read_message(sock, tag, "recv tag role");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);

            // Parse role (expected format: "Authentication successful\nYour role is: top")
            char *role_ptr = strstr((char *)dec_buf, "Your role is: ");
            if (role_ptr != NULL) {
                role_ptr += strlen("Your role is: ");
                strncpy(role, role_ptr, sizeof(role));
                role[sizeof(role) - 1] = '\0';
                // Remove any trailing whitespace or newlines
                char *end = role + strlen(role) - 1;
                while (end > role && (*end == '\n' || *end == ' ' || *end == '\r')) {
                    *end = '\0';
                    end--;
                }
            } else {
                strcpy(role, "entry");  // fallback default
                printf("Warning: Role not formatted correctly. Defaulting to: %s\n", role);
            }
            break;
        }

        if (strncmp((char *)dec_buf, fail_msg, strlen(fail_msg)) == 0) {
            close(sock);
            return 0;
        }
    }

    while (1) {          
        memset(choice, 0, sizeof(choice));                 
        show_main_menu();
        fgets(choice, sizeof(choice), stdin);
        remove_newline(choice);

        enc_len = encrypt_gcm((unsigned char *)choice, strlen(choice), key, iv, enc_buf, tag);
        send_message(sock, enc_buf, enc_len, "send choice");
        send_message(sock, tag, 16, "tag choice");

        if (choice[0] == '4') {
            printf("Exiting as requested.\n");
            break;
        } else if (choice[0] == '1') {
            // receive prompt
            enc_len = read_message(sock, buffer, "message prompt");
            read_message(sock, tag, "prompt tag");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
            printf("%s ", dec_buf);

            // get user input and send
            fgets((char *)buffer, BUFFER_SIZE, stdin);
            remove_newline((char *)buffer);
            enc_len = encrypt_gcm(buffer, strlen((char *)buffer), key, iv, enc_buf, tag);
            send_message(sock, enc_buf, enc_len, "send msg");
            send_message(sock, tag, 16, "msg tag");

            // read acknowledgment from server
            enc_len = read_message(sock, buffer, "server ack");
            read_message(sock, tag, "ack tag");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
            printf("Server: %s\n", dec_buf);

        } else if (choice[0] == '2') {
            show_server_file_menu(role, sock, key, iv);
            
        } else if (choice[0] == '3') {
            show_client_file_menu(role, sock, key, iv);
        } else {
            // read invalid choice response
            enc_len = read_message(sock, buffer, "invalid resp");
            read_message(sock, tag, "invalid tag");
            decrypt_gcm(buffer, enc_len, tag, key, iv, dec_buf);
            printf("Server: %s\n", dec_buf);
        }
    }

    close(sock);
    return 0;
}
