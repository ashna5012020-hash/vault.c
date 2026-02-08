// Rules:
// 1. One master password (stored as SHA-256 hash)
// 2. Credentials stored encrypted (XOR-based)
// 3. File-based storage
// 4. Console-based only
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

// vault_data.txt format:
// Line 1 -> SHA-256 master password hash
// Line 2+ -> site username encrypted_password

void get_hidden_input(char *password) {
    int i = 0;
    char ch;

    while ((ch = getchar()) != '\n' && i < 49) {
        password[i++] = ch;
    }
    password[i] = '\0';
}

void hash_password(const char *password, char output[65]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password, strlen(password), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(output + (i * 2), "%02x", hash[i]);

    output[64] = '\0';
}

void encryptDecrypt(char *text) {
    char key = 'K';   // encryption key
    for (int i = 0; text[i] != '\0'; i++) {
        text[i] ^= key;
    }
}

void setupMasterPassword() {
    FILE *fp = fopen("vault_data.txt", "w");
    char master[50], hash[65];

    printf("Set Master Password: ");
    get_hidden_input(master);

    hash_password(master, hash);
    fprintf(fp, "%s\n", hash);

    fclose(fp);
    printf("Master password set successfully.\n");
}

int verifyMasterPassword() {
    FILE *fp = fopen("vault_data.txt", "r");
    char stored_hash[65], input[50], input_hash[65];

    if (fp == NULL) {
        setupMasterPassword();
        return 1;
    }

    fscanf(fp, "%64s", stored_hash);
    fclose(fp);

    printf("Enter Master Password: ");
    get_hidden_input(input);

    hash_password(input, input_hash);

    if (strcmp(stored_hash, input_hash) == 0) {
        return 1;
    } else {
        printf("Incorrect master password.\n");
        return 0;
    }
}

void addCredential() {
    FILE *fp = fopen("vault_data.txt", "a");
    char site[50], user[50], pass[50];

    printf("Website: ");
    scanf("%49s", site);
    getchar();

    printf("Username: ");
    scanf("%49s", user);
    getchar();

    printf("Password: ");
    get_hidden_input(pass);

    encryptDecrypt(pass);
    fprintf(fp, "%s %s %s\n", site, user, pass);
    fclose(fp);

    printf("Credential saved.\n");
}

void viewCredentials() {
    FILE *fp = fopen("vault_data.txt", "r");
    char site[50], user[50], pass[50];

    if (fp == NULL) {
        printf("No vault found.\n");
        return;
    }

    // Skip master password
    fscanf(fp, "%s", pass);

    while (fscanf(fp, "%s %s %s", site, user, pass) != EOF) {
        encryptDecrypt(pass);
        printf("Site: %s | User: %s | Pass: %s\n", site, user, pass);
    }

    fclose(fp);
}

void menu() {
    int choice;

    while (1) {
        printf("\n1. Add Credential");
        printf("\n2. View Credentials");
        printf("\n3. Exit\n");
        printf("Choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                addCredential();
                break;
            case 2:
                viewCredentials();
                break;
            case 3:
                exit(0);
            default:
                printf("Invalid choice.\n");
        }
    }
}

int main() {
    if (verifyMasterPassword()) {
        printf("Access granted.\n");
        menu();
    }
    return 0;
}
