
/**
 * ****************************************************************************************
 * Title: Zencrypt CLI              *******************************************************
 * Developed by: Ryan Hatch         *******************************************************
 * Date: October 26th 2023          *******************************************************
 * Last Updated: October 26th 2023  *******************************************************
 * Version: 1.0                     *******************************************************
 * ****************************************************************************************
 * <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
 * <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
 * ******************************** Description: ******************************************
 *      This program, Zencrypt CLI, is a tool designed for cryptographic operations such  *
 *      as hashing, encryption, and decryption. It allows users to generate hashes with   *
 *      salt, encrypt and decrypt text using AES symmetric encryption, and manage         *
 *                                  encrypted files.                                      *  
 * ****************************************************************************************
 */

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
import javax.crypto.*;
import java.security.*;
import org.bouncycastle.openpgp.*;
import pgp.java; // This is the file that contains the PGP functions
// from pgp.java import PGPKeyRingGenerator; // This is the file that contains the PGP functions
// from pgp.java import PGPPublicKeyRing; // This is the file that contains the PGP functions
// from pgp.java import PGPSecretKeyRing; // This is the file that contains the PGP functions
// from pgp.java import pgpEncrypt; // This is the file that contains the PGP functions
// from pgp.java import pgpDecrypt; // This is the file that contains the PGP functions
// from pgp.java import exportPublicKey; // This is the file that contains the PGP functions
// from pgp.java import importPublicKey; // This is the file that contains the PGP functions



@SuppressWarnings("resource")

public class Zencrypt {

    private static final String KEY_FILE = "zencrypt_j.key";
    private static SecretKey secretKey;

    public static void main(String[] args) {
        loadKey();
        mainMenu();
    }

    private static void loadKey() {
        Path path = Paths.get(KEY_FILE);
        if (Files.exists(path)) {
            try {
                byte[] keyBytes = Files.readAllBytes(path);
                secretKey = new SecretKeySpec(keyBytes, "AES");
            } catch (IOException e) {
                System.out.println("Error reading key from file: " + e.getMessage());
            }
        } else {
            try {
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256);
                secretKey = keyGen.generateKey();
                Files.write(path, secretKey.getEncoded());
            } catch (Exception e) {
                System.out.println("Error generating or saving key: " + e.getMessage());
            }
        }
    }

    private static void mainMenu() {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("\n\n\n");
            System.out.println("<=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=>");
            System.out.println("************************|  MAIN MENU  |******************************************");
            System.out.println("<=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=>");
            System.out.println("*********************************************************************************");
            System.out.println("* 1 | Hash Generator    |********************************************************");
            System.out.println("* 2 | Encryption Manager|********************************************************");
            System.out.println("* 3 | Parse Files       |********************************************************");
            System.out.println("*********************************************************************************");
            System.out.println("* 4 | Exit              |********************************************************");
            System.out.println("*********************************************************************************");
            System.out.println("\n\n");

            System.out.print("Enter Option: ");
            String choice = scanner.nextLine();
            switch (choice) {
                case "1":
                    mainLoop();
                    break;
                case "2":
                    encryptionManager();
                    break;
                case "3":
                    parseFilesMenu();
                    break;
                case "4":
                    return;
                default:
                    System.out.println("\nInvalid Input.");
            }
        }
    }

    private static void mainLoop() {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.print("\nEnter text (type 'exit' to quit): ");
            String text = new String(System.console().readPassword());
            if ("exit".equals(text)) {
                break;
            }
            System.out.print("Enter salt value: ");
            String salt = scanner.nextLine();
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hashBytes = digest.digest((text + salt).getBytes());
                String sha256Hash = bytesToHex(hashBytes);
                System.out.println("\nOutput:\n");
                System.out.println(sha256Hash);
                printMenu(sha256Hash);
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }
    }

    private static void printMenu(String sha256Hash) {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("\n\n\n");
            System.out.println("<=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=>");
            System.out.println("************************|  HASH GEN MAIN MENU  |*********************************");
            System.out.println("<=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=>");
            System.out.println("*********************************************************************************");
            System.out.println("* 1 | Clear Clipboard   |********************************************************");
            System.out.println("* 2 | Copy Output       |********************************************************");
            System.out.println("*********************************************************************************");
            System.out.println("* 3 | Generate New Hash |********************************************************");
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
                    clearClipboard();
                    break;
                case "2":
                    copyToClipboard(sha256Hash);
                    break;
                case "3":
                    mainLoop();
                    return;
                case "4":
                    verifyHash();
                    break;
                case "5":
                    encryptionManager();
                    break;
                case "6":
                    parseFilesMenu();
                    break;
                case "7":
                    return;
                default:
                    System.out.println("\nInvalid Input.");
            }
        }
    }

    private static void verifyHash() {
        Scanner scanner = new Scanner(System.in);
        System.out.print("\nEnter the hash to verify: ");
        String inputHash = scanner.nextLine();
        System.out.print("\nEnter the original text to verify against the hash: ");
        String originalText = scanner.nextLine();
        System.out.print("Enter the salt value used during hashing: ");
        String salt = scanner.nextLine();
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest((originalText + salt).getBytes());
            String computedHash = bytesToHex(hashBytes);
            if (computedHash.equals(inputHash)) {
                System.out.println("\nHash successfully verified.");
            } else {
                System.out.println("\nVerification unsuccessful. Hash does not match.");
            }
        } catch (Exception e) {
            System.out.println("Error during verification: " + e.getMessage());
        }
    }

    private static void encryptionManager() {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("\n\n\n");
            System.out.println("<=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=>");
            System.out.println("************************|  ENCRYPT TEXT MAIN MENU  |*****************************");
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
                    clearClipboard();
                    break;
                case "2":
                    encryptText();
                    break;
                case "3":
                    decryptText();
                    break;
                case "4":
                    return;
                default:
                    System.out.println("\nInvalid Input.");
            }
        }
    }

    private static void encryptText() {
        Scanner scanner = new Scanner(System.in);
        System.out.print("\nEnter the text to encrypt: ");
        String textToEncrypt = scanner.nextLine();
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] iv = new byte[cipher.getBlockSize()];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            byte[] encryptedBytes = cipher.doFinal(textToEncrypt.getBytes());
            String encryptedText = Base64.getEncoder().encodeToString(iv) + ":" +
                    Base64.getEncoder().encodeToString(encryptedBytes);
            System.out.println("\nEncrypted Text: " + encryptedText);
            copyToClipboard(encryptedText);
        } catch (Exception e) {
            System.out.println("Error during encryption: " + e.getMessage());
        }
    }

    private static void decryptText() {
        Scanner scanner = new Scanner(System.in);
        System.out.print("\nEnter the encrypted text to decrypt: ");
        String encryptedText = scanner.nextLine();
        try {
            String[] parts = encryptedText.split(":");
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] encryptedBytes = Base64.getDecoder().decode(parts[1]);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            String decryptedText = new String(decryptedBytes);
            System.out.println("\nDecrypted Text: " + decryptedText);
        } catch (Exception e) {
            System.out.println("Error during decryption: " + e.getMessage());
        }
    }

    private static void parseFilesMenu() {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("\n\n\n");
            System.out.println("<=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=>");
            System.out.println("************************|  ENCRYPT FILE MAIN MENU  |*****************************");
            System.out.println("<=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=><=>");
            System.out.println("*********************************************************************************");
            System.out.println("* 1 | Encrypt File      |********************************************************");
            System.out.println("* 2 | Decrypt File      |********************************************************");
            System.out.println("*********************************************************************************");
            System.out.println("* 3 | Back to Main Menu |********************************************************");
            System.out.println("*********************************************************************************");
            System.out.println("\n\n");

            System.out.print("Enter Option: ");
            String choice = scanner.nextLine();
            switch (choice) {
                case "1":
                    encryptFile();
                    break;
                case "2":
                    decryptFile();
                    break;
                case "3":
                    return;
                default:
                    System.out.println("\nInvalid Input.");
            }
        }
    }

    private static void encryptFile() {
        Scanner scanner = new Scanner(System.in);
        System.out.print("\nEnter the path of the file to encrypt: ");
        String filePath = scanner.nextLine();
        Path path = Paths.get(filePath);
        if (Files.exists(path)) {
            try {
                byte[] fileBytes = Files.readAllBytes(path);
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                byte[] iv = new byte[cipher.getBlockSize()];
                new SecureRandom().nextBytes(iv);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
                byte[] encryptedBytes = cipher.doFinal(fileBytes);
                String encryptedText = Base64.getEncoder().encodeToString(iv) + ":" +
                        Base64.getEncoder().encodeToString(encryptedBytes);
                Files.write(path, encryptedText.getBytes());
                System.out.println("\nFile encrypted successfully.");
            } catch (Exception e) {
                System.out.println("Error during encryption: " + e.getMessage());
            }
        } else {
            System.out.println("\nFile not found.");
        }
    }

    private static void decryptFile() {
        Scanner scanner = new Scanner(System.in);
        System.out.print("\nEnter the path of the encrypted file to decrypt: ");
        String filePath = scanner.nextLine();
        Path path = Paths.get(filePath);
        if (Files.exists(path)) {
            try {
                byte[] fileBytes = Files.readAllBytes(path);
                String fileContent = new String(fileBytes);
                String[] parts = fileContent.split(":");
                byte[] iv = Base64.getDecoder().decode(parts[0]);
                byte[] encryptedBytes = Base64.getDecoder().decode(parts[1]);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
                byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
                Files.write(path, decryptedBytes);
                System.out.println("\nFile decrypted successfully.");
            } catch (Exception e) {
                System.out.println("Error during decryption: " + e.getMessage());
            }
        } else {
            System.out.println("\nFile not found.");
        }
    }

    private static void clearClipboard() {
        StringSelection stringSelection = new StringSelection("");
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(stringSelection, null);
        System.out.println("\n\nClipboard cleared.");
    }

    private static void copyToClipboard(String text) {
        StringSelection stringSelection = new StringSelection(text);
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(stringSelection, null);
        System.out.println("\n\nOutput copied to clipboard.");
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
