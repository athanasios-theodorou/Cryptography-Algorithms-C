#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>

#define ALPHABET_SIZE 26
#define MAX_MESSAGE_LEN 20
#define HILL_SIZE 3
#define PERM_BLOCK_SIZE 5

/* UI helpers */
static void print_separator(void);
static void print_main_menu(void);
static void print_section_title(const char *title);

/* Input helpers */
static void read_line(char *buffer, size_t size);
static int read_int_in_range(const char *prompt, int min, int max);
static void read_alpha_string(const char *prompt, char *buffer, size_t buffer_size,
                              size_t max_len, size_t min_len);

/* Utility helpers */
static void to_lowercase(char *s);
static int mod26(int x);
static int gcd_int(int a, int b);
static int mod_inverse(int a, int m);
static void print_binary_byte(unsigned char value);

/* Cipher algorithms */
static void caesar_cipher(void);
static void vigenere_cipher(void);
static void hill_cipher(void);
static void otp_cipher(void);
static void affine_cipher(void);
static void permutation_cipher(void);

int main(void) {
    while (1) {
        print_main_menu();
        print_separator();
        int choice = read_int_in_range("Select an algorithm (0-6): ", 0, 6);

        switch (choice) {
            case 1:
                caesar_cipher();
                break;
            case 2:
                vigenere_cipher();
                break;
            case 3:
                hill_cipher();
                break;
            case 4:
                otp_cipher();
                break;
            case 5:
                affine_cipher();
                break;
            case 6:
                permutation_cipher();
                break;
            case 0:
                printf("\nGoodbye.\n");
                return 0;
            default:
                /* This path is unreachable because the input is validated. */
                break;
        }

        if (!read_int_in_range("\nReturn to the main menu? (1 = yes, 0 = no): ", 0, 1)) {
            printf("\nGoodbye.\n");
            break;
        }

        printf("\n");
    }

    return 0;
}

/* Prints a consistent horizontal separator for the terminal UI. */
static void print_separator(void) {
    printf("----------------------------------------\n");
}

/* Prints the main menu exactly once per iteration. */
static void print_main_menu(void) {
    print_separator();
    printf("CRYPTOGRAPHY ALGORITHMS IN C\n");
    print_separator();
    printf("\n");
    printf("1. Caesar Cipher\n");
    printf("2. Vigenere Cipher\n");
    printf("3. Hill Cipher\n");
    printf("4. OTP Cipher (Vernam / XOR)\n");
    printf("5. Affine Cipher\n");
    printf("6. Permutation Cipher\n");
    printf("0. Exit\n");
    printf("\n");
}

/* Prints a formatted title block before each algorithm section. */
static void print_section_title(const char *title) {
    printf("\n");
    print_separator();
    printf("%s\n", title);
    print_separator();
}

/* Safely reads an entire line from standard input. */
static void read_line(char *buffer, size_t size) {
    if (fgets(buffer, (int)size, stdin) == NULL) {
        buffer[0] = '\0';
        return;
    }

    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    } else {
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF) {
            /* Discard remaining characters in the input buffer. */
        }
    }
}

/* Reads and validates an integer inside the inclusive range [min, max]. */
static int read_int_in_range(const char *prompt, int min, int max) {
    char line[128];
    char extra;
    int value;

    while (1) {
        printf("%s", prompt);
        read_line(line, sizeof(line));

        if (sscanf(line, " %d %c", &value, &extra) == 1 && value >= min && value <= max) {
            return value;
        }

        printf("Invalid input. Please enter an integer from %d to %d.\n", min, max);
    }
}

/*
 * Reads an alphabetic string, validates its length,
 * and converts it to lowercase for consistent processing.
 */
static void read_alpha_string(const char *prompt, char *buffer, size_t buffer_size,
                              size_t max_len, size_t min_len) {
    while (1) {
        bool valid = true;
        printf("%s", prompt);
        read_line(buffer, buffer_size);

        size_t len = strlen(buffer);
        if (len < min_len || len > max_len) {
            valid = false;
        }

        for (size_t i = 0; i < len && valid; ++i) {
            if (!isalpha((unsigned char)buffer[i])) {
                valid = false;
            }
        }

        if (valid) {
            to_lowercase(buffer);
            return;
        }

        printf("Invalid input. Use only letters (A-Z) with length %zu to %zu.\n",
               min_len, max_len);
    }
}

/* Converts a string to lowercase in-place. */
static void to_lowercase(char *s) {
    for (size_t i = 0; s[i] != '\0'; ++i) {
        s[i] = (char)tolower((unsigned char)s[i]);
    }
}

/* Returns a positive modulo-26 value. */
static int mod26(int x) {
    int r = x % ALPHABET_SIZE;
    return (r < 0) ? r + ALPHABET_SIZE : r;
}

/* Computes the greatest common divisor using Euclid's algorithm. */
static int gcd_int(int a, int b) {
    a = abs(a);
    b = abs(b);

    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }

    return a;
}

/* Finds the modular inverse of a modulo m, if it exists. */
static int mod_inverse(int a, int m) {
    a %= m;
    if (a < 0) {
        a += m;
    }

    for (int x = 1; x < m; ++x) {
        if ((a * x) % m == 1) {
            return x;
        }
    }

    return -1;
}

/* Prints a single byte as an 8-bit binary number. */
static void print_binary_byte(unsigned char value) {
    for (int i = 7; i >= 0; --i) {
        printf("%d", (value >> i) & 1u);
    }
}

/* ========================= Caesar Cipher ========================= */
static void caesar_cipher(void) {
    char plaintext[MAX_MESSAGE_LEN + 1];
    char encrypted[MAX_MESSAGE_LEN + 1];
    char decrypted[MAX_MESSAGE_LEN + 1];

    print_section_title("CAESAR CIPHER");

    read_alpha_string("Enter plaintext (1-20 letters): ", plaintext,
                      sizeof(plaintext), MAX_MESSAGE_LEN, 1);
    int key = read_int_in_range("Enter key (1-25): ", 1, 25);

    size_t len = strlen(plaintext);

    for (size_t i = 0; i < len; ++i) {
        int p = plaintext[i] - 'a';
        encrypted[i] = (char)(mod26(p + key) + 'a');
    }
    encrypted[len] = '\0';

    for (size_t i = 0; i < len; ++i) {
        int c = encrypted[i] - 'a';
        decrypted[i] = (char)(mod26(c - key) + 'a');
    }
    decrypted[len] = '\0';

    printf("\nEncryption\n");
    printf("Plaintext : %s\n", plaintext);
    printf("Key       : %d\n", key);
    printf("Ciphertext: %s\n", encrypted);

    printf("\nDecryption\n");
    printf("Plaintext : %s\n", decrypted);
    print_separator();
}

/* ======================== Vigenere Cipher ======================== */
static void vigenere_cipher(void) {
    char plaintext[MAX_MESSAGE_LEN + 1];
    char key[MAX_MESSAGE_LEN + 1];
    char encrypted[MAX_MESSAGE_LEN + 1];
    char decrypted[MAX_MESSAGE_LEN + 1];

    print_section_title("VIGENERE CIPHER");

    read_alpha_string("Enter plaintext (1-20 letters): ", plaintext,
                      sizeof(plaintext), MAX_MESSAGE_LEN, 1);
    read_alpha_string("Enter key (1-length of plaintext): ", key,
                      sizeof(key), strlen(plaintext), 1);

    size_t len = strlen(plaintext);
    size_t key_len = strlen(key);

    for (size_t i = 0; i < len; ++i) {
        int p = plaintext[i] - 'a';
        int k = key[i % key_len] - 'a';
        encrypted[i] = (char)(mod26(p + k) + 'a');
    }
    encrypted[len] = '\0';

    for (size_t i = 0; i < len; ++i) {
        int c = encrypted[i] - 'a';
        int k = key[i % key_len] - 'a';
        decrypted[i] = (char)(mod26(c - k) + 'a');
    }
    decrypted[len] = '\0';

    printf("\nEncryption\n");
    printf("Plaintext : %s\n", plaintext);
    printf("Key       : %s\n", key);
    printf("Ciphertext: %s\n", encrypted);

    printf("\nDecryption\n");
    printf("Plaintext : %s\n", decrypted);
    print_separator();
}

/* ========================== Hill Cipher ========================== */
static void hill_cipher(void) {
    const int key[HILL_SIZE][HILL_SIZE] = {
        {6, 24, 1},
        {13, 16, 10},
        {20, 17, 15}
    };

    char plaintext[HILL_SIZE + 1];
    char encrypted[HILL_SIZE + 1];
    char decrypted[HILL_SIZE + 1];
    int cipher_vector[HILL_SIZE];
    int inverse_key[HILL_SIZE][HILL_SIZE];

    print_section_title("HILL CIPHER");

    read_alpha_string("Enter plaintext (exactly 3 letters): ", plaintext,
                      sizeof(plaintext), HILL_SIZE, HILL_SIZE);

    /* Encrypt using the fixed 3x3 Hill key matrix. */
    for (int i = 0; i < HILL_SIZE; ++i) {
        int value = 0;
        for (int j = 0; j < HILL_SIZE; ++j) {
            value += key[i][j] * (plaintext[j] - 'a');
        }
        cipher_vector[i] = mod26(value);
        encrypted[i] = (char)(cipher_vector[i] + 'a');
    }
    encrypted[HILL_SIZE] = '\0';

    /* Compute determinant and modular inverse for the key matrix. */
    int determinant = key[0][0] * (key[1][1] * key[2][2] - key[1][2] * key[2][1])
                    - key[0][1] * (key[1][0] * key[2][2] - key[1][2] * key[2][0])
                    + key[0][2] * (key[1][0] * key[2][1] - key[1][1] * key[2][0]);
    determinant = mod26(determinant);

    int inverse_det = mod_inverse(determinant, ALPHABET_SIZE);
    if (inverse_det == -1) {
        printf("This Hill key matrix is not invertible modulo 26.\n");
        print_separator();
        return;
    }

    /* Compute the matrix of cofactors. */
    int cofactors[HILL_SIZE][HILL_SIZE];
    cofactors[0][0] =  key[1][1] * key[2][2] - key[1][2] * key[2][1];
    cofactors[0][1] = -(key[1][0] * key[2][2] - key[1][2] * key[2][0]);
    cofactors[0][2] =  key[1][0] * key[2][1] - key[1][1] * key[2][0];
    cofactors[1][0] = -(key[0][1] * key[2][2] - key[0][2] * key[2][1]);
    cofactors[1][1] =  key[0][0] * key[2][2] - key[0][2] * key[2][0];
    cofactors[1][2] = -(key[0][0] * key[2][1] - key[0][1] * key[2][0]);
    cofactors[2][0] =  key[0][1] * key[1][2] - key[0][2] * key[1][1];
    cofactors[2][1] = -(key[0][0] * key[1][2] - key[0][2] * key[1][0]);
    cofactors[2][2] =  key[0][0] * key[1][1] - key[0][1] * key[1][0];

    /* Adjugate matrix multiplied by determinant inverse modulo 26. */
    for (int i = 0; i < HILL_SIZE; ++i) {
        for (int j = 0; j < HILL_SIZE; ++j) {
            int adjugate_value = cofactors[j][i];
            inverse_key[i][j] = mod26(adjugate_value * inverse_det);
        }
    }

    /* Decrypt the ciphertext vector using the inverse key matrix. */
    for (int i = 0; i < HILL_SIZE; ++i) {
        int value = 0;
        for (int j = 0; j < HILL_SIZE; ++j) {
            value += inverse_key[i][j] * cipher_vector[j];
        }
        decrypted[i] = (char)(mod26(value) + 'a');
    }
    decrypted[HILL_SIZE] = '\0';

    printf("\nEncryption\n");
    printf("Plaintext : %s\n", plaintext);
    printf("Key matrix:\n");
    for (int i = 0; i < HILL_SIZE; ++i) {
        printf("[%2d %2d %2d]\n", key[i][0], key[i][1], key[i][2]);
    }
    printf("Ciphertext: %s\n", encrypted);

    printf("\nDecryption\n");
    printf("Inverse key matrix modulo 26:\n");
    for (int i = 0; i < HILL_SIZE; ++i) {
        printf("[%2d %2d %2d]\n", inverse_key[i][0], inverse_key[i][1], inverse_key[i][2]);
    }
    printf("Plaintext : %s\n", decrypted);
    print_separator();
}

/* ========================= OTP Cipher ============================ */
static void otp_cipher(void) {
    char plaintext[MAX_MESSAGE_LEN + 1];
    char key[MAX_MESSAGE_LEN + 1];
    char encrypted[MAX_MESSAGE_LEN + 1];
    char decrypted[MAX_MESSAGE_LEN + 1];

    print_section_title("OTP CIPHER");
    printf("1. Vernam (mod 26)\n");
    printf("2. XOR\n");

    int mode = read_int_in_range("Select mode (1-2): ", 1, 2);
    read_alpha_string("Enter plaintext (1-20 letters): ", plaintext,
                      sizeof(plaintext), MAX_MESSAGE_LEN, 1);

    while (1) {
        read_alpha_string("Enter key (same length as plaintext): ", key,
                          sizeof(key), MAX_MESSAGE_LEN, 1);
        if (strlen(key) == strlen(plaintext)) {
            break;
        }
        printf("The key must have exactly %zu letters.\n", strlen(plaintext));
    }

    size_t len = strlen(plaintext);

    if (mode == 1) {
        for (size_t i = 0; i < len; ++i) {
            encrypted[i] = (char)(mod26((plaintext[i] - 'a') + (key[i] - 'a')) + 'a');
        }
        encrypted[len] = '\0';

        for (size_t i = 0; i < len; ++i) {
            decrypted[i] = (char)(mod26((encrypted[i] - 'a') - (key[i] - 'a')) + 'a');
        }
        decrypted[len] = '\0';
    } else {
        for (size_t i = 0; i < len; ++i) {
            encrypted[i] = (char)(plaintext[i] ^ key[i]);
        }
        encrypted[len] = '\0';

        for (size_t i = 0; i < len; ++i) {
            decrypted[i] = (char)(encrypted[i] ^ key[i]);
        }
        decrypted[len] = '\0';
    }

    printf("\nEncryption\n");
    printf("Plaintext : %s\n", plaintext);
    printf("Key       : %s\n", key);

    if (mode == 2) {
        printf("Plaintext (binary): ");
        for (size_t i = 0; i < len; ++i) {
            print_binary_byte((unsigned char)plaintext[i]);
            printf(" ");
        }
        printf("\n");

        printf("Key       (binary): ");
        for (size_t i = 0; i < len; ++i) {
            print_binary_byte((unsigned char)key[i]);
            printf(" ");
        }
        printf("\n");

        printf("Ciphertext(binary): ");
        for (size_t i = 0; i < len; ++i) {
            print_binary_byte((unsigned char)encrypted[i]);
            printf(" ");
        }
        printf("\n");
    } else {
        printf("Ciphertext: %s\n", encrypted);
    }

    printf("\nDecryption\n");
    printf("Plaintext : %s\n", decrypted);
    print_separator();
}

/* ======================== Affine Cipher ========================== */
static void affine_cipher(void) {
    char plaintext[MAX_MESSAGE_LEN + 1];
    char encrypted[MAX_MESSAGE_LEN + 1];
    char decrypted[MAX_MESSAGE_LEN + 1];

    print_section_title("AFFINE CIPHER");

    read_alpha_string("Enter plaintext (1-20 letters): ", plaintext,
                      sizeof(plaintext), MAX_MESSAGE_LEN, 1);

    int a;
    while (1) {
        a = read_int_in_range("Enter multiplicative key a (1-25, gcd(a,26)=1): ", 1, 25);
        if (gcd_int(a, ALPHABET_SIZE) == 1) {
            break;
        }
        printf("Invalid value for 'a'. It must be coprime with 26.\n");
    }

    int b = read_int_in_range("Enter additive key b (0-25): ", 0, 25);
    int a_inverse = mod_inverse(a, ALPHABET_SIZE);
    size_t len = strlen(plaintext);

    for (size_t i = 0; i < len; ++i) {
        encrypted[i] = (char)(mod26(a * (plaintext[i] - 'a') + b) + 'a');
    }
    encrypted[len] = '\0';

    for (size_t i = 0; i < len; ++i) {
        decrypted[i] = (char)(mod26(a_inverse * ((encrypted[i] - 'a') - b)) + 'a');
    }
    decrypted[len] = '\0';

    printf("\nEncryption\n");
    printf("Plaintext : %s\n", plaintext);
    printf("Key       : (a=%d, b=%d)\n", a, b);
    printf("Ciphertext: %s\n", encrypted);

    printf("\nDecryption\n");
    printf("Plaintext : %s\n", decrypted);
    print_separator();
}

/* ===================== Permutation Cipher ======================== */
static void permutation_cipher(void) {
    const int key[PERM_BLOCK_SIZE] = {3, 1, 4, 2, 0};

    char plaintext[MAX_MESSAGE_LEN + 1];
    char padded[MAX_MESSAGE_LEN + PERM_BLOCK_SIZE + 1];
    char encrypted[MAX_MESSAGE_LEN + PERM_BLOCK_SIZE + 1];
    char decrypted[MAX_MESSAGE_LEN + PERM_BLOCK_SIZE + 1];

    print_section_title("PERMUTATION CIPHER");

    read_alpha_string("Enter plaintext (1-20 letters): ", plaintext,
                      sizeof(plaintext), MAX_MESSAGE_LEN, 1);

    size_t original_len = strlen(plaintext);
    size_t padded_len = original_len;
    strcpy(padded, plaintext);

    /* Pad the final block with 'x' so the permutation can be applied safely. */
    while (padded_len % PERM_BLOCK_SIZE != 0) {
        padded[padded_len++] = 'x';
    }
    padded[padded_len] = '\0';

    for (size_t block = 0; block < padded_len; block += PERM_BLOCK_SIZE) {
        for (int j = 0; j < PERM_BLOCK_SIZE; ++j) {
            encrypted[block + j] = padded[block + key[j]];
        }
    }
    encrypted[padded_len] = '\0';

    for (size_t block = 0; block < padded_len; block += PERM_BLOCK_SIZE) {
        for (int j = 0; j < PERM_BLOCK_SIZE; ++j) {
            decrypted[block + key[j]] = encrypted[block + j];
        }
    }
    decrypted[padded_len] = '\0';

    printf("\nEncryption\n");
    printf("Plaintext         : %s\n", plaintext);
    printf("Permutation key   : [0->3, 1->1, 2->4, 3->2, 4->0]\n");
    printf("Padded plaintext  : %s\n", padded);
    printf("Ciphertext        : %s\n", encrypted);

    printf("\nDecryption\n");
    printf("Recovered plaintext: %s\n", decrypted);
    if (padded_len != original_len) {
        printf("Note: the plaintext was padded with 'x' to fill the final block.\n");
    }
    print_separator();
}
