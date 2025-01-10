const crypto = require('crypto');
const readline = require('readline');
const fs = require('fs');
const openpgp = require('openpgp');
const inquirer = require('inquirer');

// Generate SHA-256 hash
function generateHash(text, salt) {
    const hash = crypto.createHash('sha256');
    hash.update(text + salt);
    return hash.digest('hex');
}

// Symmetric encryption using AES
function encryptText(text, secretKey) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secretKey), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// Symmetric decryption
function decryptText(text, secretKey) {
    let textParts = text.split(':');
    let iv = Buffer.from(textParts.shift(), 'hex');
    let encryptedText = Buffer.from(textParts.join(':'), 'hex');
    let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secretKey), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// PGP encryption
async function encryptPGP(message, publicKey) {
    const { data: encrypted } = await openpgp.encrypt({
        message: openpgp.message.fromText(message),
        publicKeys: (await openpgp.key.readArmored(publicKey)).keys
    });
    return encrypted;
}

// PGP decryption
async function decryptPGP(encryptedMessage, privateKey, passphrase) {
    const privKeyObj = (await openpgp.key.readArmored(privateKey)).keys[0];
    await privKeyObj.decrypt(passphrase);

    const { data: decrypted } = await openpgp.decrypt({
        message: await openpgp.message.readArmored(encryptedMessage),
        privateKeys: [privKeyObj]
    });
    return decrypted;
}

// File encryption
function encryptFile(inputFile, outputFile, secretKey) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secretKey), iv);
    const input = fs.createReadStream(inputFile);
    const output = fs.createWriteStream(outputFile);

    input.pipe(cipher).pipe(output);
}

// File decryption
function decryptFile(inputFile, outputFile, secretKey) {
    let textParts = fs.readFileSync(inputFile, 'utf8').split(':');
    let iv = Buffer.from(textParts.shift(), 'hex');
    let encryptedText = Buffer.from(textParts.join(':'), 'hex');
    let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secretKey), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    fs.writeFileSync(outputFile, decrypted);
}

// Generate PGP keys
async function generatePGPKeys(name, email, passphrase) {
    const { privateKeyArmored, publicKeyArmored } = await openpgp.generateKey({
        userIds: [{ name, email }],
        curve: 'ed25519', // ECC curve name
        passphrase
    });

    return { privateKeyArmored, publicKeyArmored };
}

// Save key to file
function saveKeyToFile(key, filename) {
    fs.writeFileSync(filename, key, 'utf8');
}

// Load key from file
function loadKeyFromFile(filename) {
    return fs.readFileSync(filename, 'utf8');
}

// CLI Interface
async function mainMenu() {
    const answers = await inquirer.prompt([
        {
            type: 'list',
            name: 'action',
            message: 'What do you want to do?',
            choices: ['Generate PGP Keys', 'Hash Text', 'Encrypt Text', 'Decrypt Text', 'Encrypt File', 'Decrypt File', 'PGP Encrypt', 'PGP Decrypt', 'Exit']
        }
    ]);

    switch (answers.action) {
        case 'Generate PGP Keys':
            const keyInfo = await inquirer.prompt([
                { type: 'input', name: 'name', message: 'Enter your name:' },
                { type: 'input', name: 'email', message: 'Enter your email:' },
                { type: 'password', name: 'passphrase', message: 'Enter a passphrase:', mask: '*' }
            ]);
            const keys = await generatePGPKeys(keyInfo.name, keyInfo.email, keyInfo.passphrase);
            saveKeyToFile(keys.privateKeyArmored, 'privateKey.asc');
            saveKeyToFile(keys.publicKeyArmored, 'publicKey.asc');
            console.log('Keys generated and saved as privateKey.asc and publicKey.asc');
            break;
        // Implement other cases...
        case 'Exit':
            process.exit();
    }
}

mainMenu();