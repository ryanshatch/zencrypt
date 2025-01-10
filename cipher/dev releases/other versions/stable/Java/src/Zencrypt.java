
/********************************************************************************************
 * Title: Zencrypt CLI              |********************************************************
 * Developed by: Ryan Hatch         |********************************************************
 * Date: October 26th 2023          |********************************************************
 * Last Updated: November 23rd 2023 |********************************************************
 * Version: 1.0                     |********************************************************
 * ******************************************************************************************
 * <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
 * <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
 *                                                                                          *
 * ******************************** Description: ********************************************
 *                                                                                          *
 *      This program, Zencrypt CLI, is a tool designed for cryptographic operations such    *
 *      as hashing, encryption, and decryption. It allows users to generate hashes with     *
 *      salt, encrypt and decrypt text using AES symmetric encryption, and manage           *
 *                                  encrypted files.                                        *
 *                                                                                          *  
 *******************************************************************************************/

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;

@SuppressWarnings("resource") // Suppresses warnings for scanner not being closed

public class Zencrypt { // Main class for Zencrypt CLI

    private static final String KEY_FILE = "zencrypt_j.key"; // Key file name for AES encryption
    private static SecretKey secretKey;

    public static void main(String[] args) { // Main method for Zencrypt CLI
        loadKey(); // Load key from file or generate new key if .key does not exist
        mainMenu(); // Main menu for Zencrypt CLI (Hash Generator, Encrypt Text, Encrypt Files, and
                    // Exit)
    }

    private static void loadKey() { // Load key from file or generate new key if .key does not exist
        Path path = Paths.get(KEY_FILE); // Path to key file for AES encryption
        if (Files.exists(path)) { // If key file exists, load key from file
            try {
                byte[] keyBytes = Files.readAllBytes(path);
                secretKey = new SecretKeySpec(keyBytes, "AES");
            } catch (IOException e) {
                System.out.println("Error reading key from file: " + e.getMessage()); // Error reading key from file
            }
        } else {
            try {
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256);
                secretKey = keyGen.generateKey();
                Files.write(path, secretKey.getEncoded());
            } catch (Exception e) {
                System.out.println("Error generating or saving key: " + e.getMessage()); // Error generating or saving
                                                                                         // key
            }
        }
    }

    private static void mainMenu() { // Main menu for Zencrypt CLI
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("\n\n\n");
            System.out.println("<=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=>");
            System.out.println("************************|  Main Menu  |******************************************");
            System.out.println("<=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=>");
            System.out.println("*********************************************************************************");
            System.out.println("* 1 | Hashing Manager   |********************************************************");
            System.out.println("* 2 | Encrypt Text      |********************************************************");
            System.out.println("* 3 | Encrypt Files     |********************************************************");
            System.out.println("*********************************************************************************");
            System.out.println("* 4 | Exit              |********************************************************");
            System.out.println("*********************************************************************************");
            System.out.println("\n\n");

            System.out.print("Enter Option: ");
            String choice = scanner.nextLine();
            switch (choice) {
                case "1":
                    mainLoop(); // Hash Manager
                    break;
                case "2":
                    encryptionManager(); // Encrypt Text
                    break;
                case "3":
                    parseFilesMenu(); // Encrypt Files
                    break;
                case "4": // Exit
                    return;
                default:
                    System.out.println("\nInvalid Input."); // Invalid Input
            }
        }
    }

    private static void mainLoop() { // Hash Manager
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.print("\nEnter text (type 'exit' to quit): "); // Enter text to hash
            String text = new String(System.console().readPassword());
            if ("exit".equals(text)) {
                break;
            }
            System.out.print("Enter salt value: "); // Enter salt value
            String salt = scanner.nextLine();
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256"); // Hash text with salt
                byte[] hashBytes = digest.digest((text + salt).getBytes());
                String sha256Hash = bytesToHex(hashBytes);
                System.out.println("\nOutput:\n"); // Print hash to console
                System.out.println(sha256Hash);
                printMenu(sha256Hash);
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }
    }

    private static void printMenu(String sha256Hash) { // Print menu for Hash Manager
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("\n\n\n");
            System.out.println("<=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=>");
            System.out.println("************************|  Hash Manager  |***************************************");
            System.out.println("<=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=>");
            System.out.println("*********************************************************************************");
            System.out.println("* 1 | Clear Clipboard   |********************************************************");
            System.out.println("* 2 | Copy Output       |********************************************************");
            System.out.println("*********************************************************************************");
            System.out.println("* 3 | Generate Hash     |********************************************************");
            System.out.println("* 4 | Verify Hash       |********************************************************");
            System.out.println("*********************************************************************************");
            System.out.println("* 5 | Encryption Menu   |********************************************************");
            System.out.println("* 6 | Parse Files       |********************************************************");
            System.out.println("*********************************************************************************");
            System.out.println("* 7 | Exit              |********************************************************");
            System.out.println("*********************************************************************************");
            System.out.println("\n\n");

            System.out.print("Enter Option: ");
            String choice = scanner.nextLine();
            switch (choice) {
                case "1":
                    clearClipboard(); // Clear Clipboard
                    break;
                case "2":
                    copyToClipboard(sha256Hash); // Copy Output
                    break;
                case "3":
                    mainLoop(); // Generate New Hash
                    return;
                case "4":
                    verifyHash(); // Verify Hash
                    break;
                case "5":
                    encryptionManager(); // Encryption Menu
                    break;
                case "6":
                    parseFilesMenu(); // Parse Files
                    break;
                case "7": // Exit
                    return;
                default:
                    System.out.println("\nInvalid Input."); // Invalid Input
            }
        }
    }

    private static void verifyHash() { // Verify Hash
        Scanner scanner = new Scanner(System.in);
        System.out.print("\nEnter the hash to verify: "); // Enter hash to verify
        String inputHash = scanner.nextLine();
        System.out.print("\nEnter the original text to verify against the hash: ");
        String originalText = scanner.nextLine();
        System.out.print("Enter the salt value used during hashing: ");
        String salt = scanner.nextLine();
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest((originalText + salt).getBytes()); // Hash original text with salt
            String computedHash = bytesToHex(hashBytes); // Compare computed hash to input hash
            if (computedHash.equals(inputHash)) { // Print verification result to console
                System.out.println("\nHash successfully verified.");
            } else {
                System.out.println("\nVerification unsuccessful. Hash does not match.");
            }
        } catch (Exception e) { // Error during verification
            System.out.println("Error during verification: " + e.getMessage());
        }
    }

    private static void encryptionManager() { // Encryption Text with AES Symmetric Encryption
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("\n\n\n");
            System.out.println("<=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=>");
            System.out.println("************************|  Encrypt Text  |***************************************");
            System.out.println("<=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=>");
            System.out.println("*********************************************************************************");
            System.out.println("* 1 | Clear Clipboard   |********************************************************");
            System.out.println("*********************************************************************************");
            System.out.println("* 2 | Encrypt           |********************************************************");
            System.out.println("* 3 | Decrypt           |********************************************************");
            System.out.println("*********************************************************************************");
            System.out.println("* 4 | Back to Hash Gen  |********************************************************");
            System.out.println("*********************************************************************************");
            System.out.println("\n\n");

            System.out.print("Enter Option: ");
            String choice = scanner.nextLine();
            switch (choice) {
                case "1":
                    clearClipboard(); // Clear Clipboard
                    break;
                case "2":
                    encryptText(); // Encrypt
                    break;
                case "3":
                    decryptText(); // Decrypt
                    break;
                case "4": // Back to Hash Gen
                    return;
                default:
                    System.out.println("\nInvalid Input."); // Invalid Input
            }
        }
    }

    private static void encryptText() { // Encrypt Text with AES Symmetric Encryption
        Scanner scanner = new Scanner(System.in);
        System.out.print("\nEnter the text to encrypt: "); // Enter text to encrypt
        String textToEncrypt = scanner.nextLine();
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Encrypt text
            byte[] iv = new byte[cipher.getBlockSize()];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            byte[] encryptedBytes = cipher.doFinal(textToEncrypt.getBytes());
            String encryptedText = Base64.getEncoder().encodeToString(iv) + ":" +
                    Base64.getEncoder().encodeToString(encryptedBytes);
            System.out.println("\nEncrypted Text: " + encryptedText); // Print encrypted text to console
            copyToClipboard(encryptedText);
        } catch (Exception e) {
            System.out.println("Error during encryption: " + e.getMessage()); // Error during encryption
        }
    }

    private static void decryptText() { // Decrypt Text with AES Symmetric Encryption
        Scanner scanner = new Scanner(System.in);
        System.out.print("\nEnter the encrypted text to decrypt: "); // Enter encrypted text to decrypt
        String encryptedText = scanner.nextLine();
        try {
            String[] parts = encryptedText.split(":"); // Decrypt text
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] encryptedBytes = Base64.getDecoder().decode(parts[1]);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Print decrypted text to console
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            String decryptedText = new String(decryptedBytes);
            System.out.println("\nDecrypted Text: " + decryptedText);
        } catch (Exception e) {
            System.out.println("Error during decryption: " + e.getMessage()); // Error during decryption
        }
    }

    private static void parseFilesMenu() { // Ecnrypt Files with AES Symmetric Encryption
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("\n\n\n");
            System.out.println("<=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=>");
            System.out.println("************************|  Encrypt Files  |**************************************");
            System.out.println("<=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=>");
            System.out.println("*********************************************************************************");
            System.out.println("* 1 | Encrypt           |********************************************************");
            System.out.println("* 2 | Decrypt           |********************************************************");
            System.out.println("*********************************************************************************");
            System.out.println("* 3 | Back to Main Menu |********************************************************");
            System.out.println("*********************************************************************************");
            System.out.println("\n\n");

            System.out.print("Enter Option: ");
            String choice = scanner.nextLine();
            switch (choice) {
                case "1":
                    encryptFile(); // Encrypt File
                    break;
                case "2":
                    decryptFile(); // Decrypt File
                    break;
                case "3":
                    return; // Back to Main Menu
                default:
                    System.out.println("\nInvalid Input."); // Invalid Input
            }
        }
    }

    private static void encryptFile() { // Encrypt File with AES Symmetric Encryption and save to file
        Scanner scanner = new Scanner(System.in);
        System.out.print("\nEnter the path of the file to encrypt: "); // Enter path of file to encrypt
        String filePath = scanner.nextLine();
        Path path = Paths.get(filePath);
        if (Files.exists(path)) {
            try {
                byte[] fileBytes = Files.readAllBytes(path);
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Encrypt file
                byte[] iv = new byte[cipher.getBlockSize()];
                new SecureRandom().nextBytes(iv);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
                byte[] encryptedBytes = cipher.doFinal(fileBytes);
                String encryptedText = Base64.getEncoder().encodeToString(iv) + ":" +
                        Base64.getEncoder().encodeToString(encryptedBytes);
                Files.write(path, encryptedText.getBytes());
                System.out.println("\nFile encrypted successfully."); // Print encrypted file to console
            } catch (Exception e) {
                System.out.println("Error during encryption: " + e.getMessage()); // Error during encryption
            }
        } else {
            System.out.println("\nFile not found."); // File not found
        }
    }

    private static void decryptFile() { // Decrypt File with AES Symmetric Encryption and save to file
        Scanner scanner = new Scanner(System.in);
        System.out.print("\nEnter the path of the encrypted file to decrypt: "); // Enter path of encrypted file to
                                                                                 // decrypt
        String filePath = scanner.nextLine();
        Path path = Paths.get(filePath);
        if (Files.exists(path)) {
            try {
                byte[] fileBytes = Files.readAllBytes(path); // Decrypt file
                String fileContent = new String(fileBytes);
                String[] parts = fileContent.split(":");
                byte[] iv = Base64.getDecoder().decode(parts[0]);
                byte[] encryptedBytes = Base64.getDecoder().decode(parts[1]);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Print decrypted file to console
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
                byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
                Files.write(path, decryptedBytes);
                System.out.println("\nFile decrypted successfully."); // File decrypted successfully
            } catch (Exception e) {
                System.out.println("Error during decryption: " + e.getMessage()); // Error during decryption
            }
        } else {
            System.out.println("\nFile not found."); // File not found
        }
    }

    private static void clearClipboard() { // Clear Clipboard
        StringSelection stringSelection = new StringSelection("");
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(stringSelection, null);
        System.out.println("\n\nClipboard cleared.");
    }

    private static void copyToClipboard(String text) { // Copy Output to Clipboard
        StringSelection stringSelection = new StringSelection(text);
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(stringSelection, null);
        System.out.println("\n\nOutput copied to clipboard.");
    }

    private static String bytesToHex(byte[] bytes) { // Convert bytes to hex string to format the hash output
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) { // For each byte in the byte array
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0'); // Add leading zero if hex value is only one character
            }
            hexString.append(hex); // Append hex value to string
        }
        return hexString.toString();
    }
}