import Foundation
import CommonCrypto

// MARK: - Helper Functions

func sha256(_ input: String) -> String {
    let data = Data(input.utf8)
    var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
    data.withUnsafeBytes {
        _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
    }
    return hash.map { String(format: "%02x", $0) }.joined()
}

func aesEncrypt(_ string: String, key: String) -> String? {
    // Implement AES encryption here
    // Placeholder implementation
    return "Encrypted: \(string)"
}

func aesDecrypt(_ string: String, key: String) -> String? {
    // Implement AES decryption here
    // Placeholder implementation
    return "Decrypted: \(string)"
}

// MARK: - Main Menu

func mainMenu() {
    var shouldContinue = true
    while shouldContinue {
        print("\n1. Generate SHA256 Hash\n2. Encrypt Text\n3. Decrypt Text\n4. Exit")
        print("Enter your choice: ", terminator: "")
        if let choice = readLine() {
            switch choice {
            case "1":
                generateHash()
            case "2":
                encryptText()
            case "3":
                decryptText()
            case "4":
                shouldContinue = false
            default:
                print("Invalid option.")
            }
        }
    }
}

// MARK: - Menu Functions

func generateHash() {
    print("Enter text to hash: ", terminator: "")
    if let input = readLine() {
        let hash = sha256(input)
        print("SHA256 Hash: \(hash)")
    }
}

func encryptText() {
    print("Enter text to encrypt: ", terminator: "")
    if let text = readLine() {
        // Use a predefined or user-input key
        let key = "your-encryption-key"
        if let encrypted = aesEncrypt(text, key: key) {
            print("Encrypted Text: \(encrypted)")
        }
    }
}

func decryptText() {
    print("Enter text to decrypt: ", terminator: "")
    if let text = readLine() {
        // Use the same key used for encryption
        let key = "your-encryption-key"
        if let decrypted = aesDecrypt(text, key: key) {
            print("Decrypted Text: \(decrypted)")
        }
    }
}

// MARK: - Main Execution

mainMenu()