# Password Vault with Salted Hashing 🔐

A secure Java-based password vault implementation that demonstrates proper password storage techniques using salted hashing to protect against common attack vectors.

## 🎯 Overview

This project implements a secure password storage system that:
- Uses **SHA-256 hashing** with cryptographically secure random salts
- Prevents **rainbow table attacks** through salt randomization
- Detects **weak passwords** from a breach database
- Generates **strong password suggestions**
- Provides **password verification** functionality

## 🔧 Features

### Core Security Features
- **Salted Hashing**: Each password is hashed with a unique 16-byte random salt
- **SHA-256 Algorithm**: Industry-standard cryptographic hash function
- **Secure Random**: Uses `SecureRandom` for cryptographically strong salt generation
- **Base64 Encoding**: Safe storage format for binary hash and salt data

### User Protection
- **Weak Password Detection**: Identifies common breached passwords
- **Strong Password Generation**: Creates secure 12-character passwords
- **Password Verification**: Validates user input against stored hashes
- **Debug Information**: Optional hash comparison for development

## 🚀 Getting Started

### Prerequisites
- Java 8 or higher
- No external dependencies required (uses standard Java libraries)

### Installation
1. Clone the repository:
```bash
git clone https://github.com/yourusername/password-vault-salted-hashing.git
cd password-vault-salted-hashing
```

2. Compile the Java file:
```bash
javac PasswordVault.java
```

3. Run the application:
```bash
java PasswordVault
```

## 📖 Usage

### Basic Workflow
1. **Enter Username**: Provide a username for the vault
2. **Enter Password**: Input your desired password
3. **Weak Password Check**: System alerts if password is compromised
4. **Secure Storage**: Password is salted, hashed, and stored
5. **Verification**: Re-enter password to verify storage integrity

### Example Session
```
Welcome to the Password Vault!
Enter username: john_doe
Enter password: password123
[!] Weak password.
[+] Try this strong password suggestion: Xk9#mP2$vL8@
[?] Password stored securely.

User:            john_doe
Salt (Base64):   randomSaltBase64String==
Hashed Password: hashedPasswordBase64String==

Re-enter password to verify: password123
Password Match:  true
```

## 🔒 Security Implementation

### Salted Hashing Process
1. **Salt Generation**: 16-byte random salt using `SecureRandom`
2. **Hash Computation**: SHA-256(salt + password)
3. **Secure Storage**: Base64-encoded hash and salt stored separately
4. **Verification**: Input password hashed with stored salt for comparison

### Protection Against Common Attacks
- **Rainbow Table Attacks**: Unique salts prevent precomputed hash lookups
- **Dictionary Attacks**: Weak password detection with breach database
- **Brute Force**: Cryptographically secure hashing increases computation cost

## 🏗️ Architecture

### Core Components
```
PasswordVault.java
├── userHashes (HashMap)     # Stores username -> hashed password
├── userSalts (HashMap)      # Stores username -> salt
├── breached (List)          # Common weak passwords database
├── generateSalt()           # Cryptographic salt generation
├── hashPassword()           # SHA-256 salted hashing
├── verifyPassword()         # Password verification
├── isWeakPassword()         # Breach detection
└── generateStrongPassword() # Secure password generation
```

### Data Flow
```
User Input → Weak Check → Salt Generation → SHA-256 Hashing → Base64 Encoding → Storage
```

## ⚠️ Security Considerations

### Current Implementation
- **Development Purpose**: Designed for educational/demonstration use
- **In-Memory Storage**: Data lost when application terminates
- **Debug Output**: Hash values printed for verification (remove in production)

### Production Recommendations
- **Persistent Storage**: Use encrypted database or secure file system
- **Key Stretching**: Implement PBKDF2, bcrypt, or Argon2 for better security
- **Rate Limiting**: Add authentication attempt restrictions
- **Secure Memory**: Clear sensitive data from memory after use
- **Logging**: Remove debug prints and implement secure logging

## 🔧 Configuration

### Customizable Parameters
- **Salt Length**: Currently 16 bytes (line 51)
- **Hash Algorithm**: SHA-256 (line 56)
- **Password Length**: Default 12 characters (line 80)
- **Character Set**: Alphanumeric + special characters (line 81)

### Breach Database
Update the `breached` list with additional compromised passwords:
```java
static List<String> breached = Arrays.asList(
    "admin123", "password", "12345678", "iloveyou", "qwerty", "abc123"
    // Add more compromised passwords here
);
```

## 🧪 Testing

### Manual Testing
1. Test weak password detection with common passwords
2. Verify password storage and retrieval
3. Test strong password generation
4. Validate hash consistency

### Security Testing
- Verify unique salts for identical passwords
- Test password verification with correct/incorrect inputs
- Validate Base64 encoding/decoding integrity

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/enhancement`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/enhancement`)
5. Create a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Resources

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [Java Cryptography Architecture](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html)

## 📊 Performance

- **Hash Time**: ~1ms per password (SHA-256)
- **Salt Generation**: ~0.1ms per salt
- **Memory Usage**: Minimal (HashMap storage)
- **Scalability**: Suitable for small to medium user bases

## 🐛 Known Issues

- In-memory storage (data not persistent)
- Debug output in production code
- Single-threaded implementation
- No user session management

## 🎓 Educational Value

This implementation demonstrates:
- Proper password hashing techniques
- Salt generation and usage
- Secure random number generation
- Hash verification process
- Common security vulnerabilities and mitigations

---

![image](https://github.com/user-attachments/assets/320502bb-d402-4014-9836-677719bba2af)


**⚠️ Disclaimer**: This is an educational implementation. For production use, consider established password management libraries and additional security measures.
