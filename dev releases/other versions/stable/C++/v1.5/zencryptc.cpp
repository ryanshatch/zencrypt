#include <iostream>
#include <fstream>
#include <string>
#include "aes.h"
#include "modes.h"
#include "osrng.h"
#include "files.h"

void encrypt_file(const std::string& input_file, const std::string& output_file, const std::string& password) { // This function encrypts a file
    CryptoPP::AutoSeededRandomPool prng;

    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());    // Generate a random key

    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));    // Generate a random IV

    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

    CryptoPP::FileSource fs(input_file.c_str(), true,
        new CryptoPP::StreamTransformationFilter(cbcEncryption, 
            new CryptoPP::FileSink(output_file.c_str()) // Encrypt the file
        )
    );
}

void decrypt_file(const std::string& input_file, const std::string& output_file, const std::string& password) { // This function decrypts a file
    CryptoPP::AutoSeededRandomPool prng;

    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);   // Generate a random key
    prng.GenerateBlock(key, key.size());

    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));   // Generate a random IV

    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

    CryptoPP::FileSource fs(input_file.c_str(), true,
        new CryptoPP::StreamTransformationFilter(cbcDecryption,
            new CryptoPP::FileSink(output_file.c_str()) // Decrypt the file
        )
    );
}

int main() {
    std::string input_file, output_file, password;  // Get the input file, output file, and password from the user

    std::cout << "Enter the path to the file to encrypt: ";
    std::cin >> input_file;
    std::cout << "Enter the path for the encrypted file: ";
    std::cin >> output_file;
    std::cout << "Enter the encryption password: ";
    std::cin >> password;

    encrypt_file(input_file, output_file, password);    // Encrypt the file
    std::cout << "Encryption complete.\n";

    std::cout << "Enter the path to the encrypted file: ";
    std::cin >> input_file;
    std::cout << "Enter the path for the decrypted file: ";
    std::cin >> output_file;
    std::cout << "Enter the decryption password: ";
    std::cin >> password;

    decrypt_file(input_file, output_file, password);    // Decrypt the file
    std::cout << "Decryption complete.\n";

    return 0;
}