# CRYPTOGRAPHY ALGORITHMS IN C

Implementation of classical cryptographic algorithms in the C programming language.
This project provides a simple command-line interface where the user can select and execute different encryption algorithms.

## Implemented Algorithms

The program currently supports the following cryptographic algorithms:

* Caesar Cipher
* Vigenere Cipher
* Hill Cipher
* OTP Cipher (Vernam / XOR)
* Affine Cipher
* Permutation Cipher

## Program Interface

When the program starts, the user is presented with the following menu:

```
----------------------------------------
CRYPTOGRAPHY ALGORITHMS IN C
----------------------------------------

1. Caesar Cipher
2. Vigenere Cipher
3. Hill Cipher
4. OTP Cipher (Vernam / XOR)
5. Affine Cipher
6. Permutation Cipher
0. Exit

----------------------------------------
Select an algorithm (0-6):
```

After selecting an algorithm, the program asks for the required inputs (plaintext, key, etc.) and performs encryption and decryption.

## Example Execution

Example using the **Caesar Cipher**:

```
----------------------------------------
CAESAR CIPHER
----------------------------------------

Enter plaintext (1-20 letters): hello
Enter key (1-25): 3

Encryption
Plaintext : hello
Key       : 3
Ciphertext: khoor

Decryption
Plaintext : hello
```

## Technologies

* C
* Standard C Library
