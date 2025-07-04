import java.security.*;
import java.util.*;

public class PasswordVault {

    static Map<String, String> userHashes = new HashMap<>();    // Maps to store hashed password and salt per user
    static Map<String, String> userSalts = new HashMap<>();

    static List<String> breached = Arrays.asList(
        "admin123", "password", "12345678", "iloveyou", "qwerty", "abc123"
    );    // List of common weak passwords

    public static void main(String[] args) {
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.println("Welcome to the Password Vault!");
            System.out.print("Enter username: ");
            String username = scanner.nextLine();

            System.out.print("Enter password: ");
            String password = scanner.nextLine();

            // Check for weak password
            if (isWeakPassword(password)) {
                System.out.println("[!] Weak password.");
                String suggestion = generateStrongPassword(12);
                System.out.println("[+] Try this strong password suggestion: " + suggestion);
            }

            // Generate salt and hash the password
            byte[] salt = generateSalt();
            byte[] hashedPassword = hashPassword(password, salt);

            // Convert to Base64
            String saltBase64 = Base64.getEncoder().encodeToString(salt);
            String hashBase64 = Base64.getEncoder().encodeToString(hashedPassword);

            // Store credentials
            userHashes.put(username, hashBase64);
            userSalts.put(username, saltBase64);

            // Show confirmation
            System.out.println("[?] Password stored securely.\n");

            // Display stored values
            System.out.println("User:            " + username);
            System.out.println("Salt (Base64):   " + saltBase64);
            System.out.println("Hashed Password: " + hashBase64);

            // Ask user to re-enter password to verify
            System.out.print("\nRe-enter password to verify: ");
            String inputPassword = scanner.nextLine();

            // Verify and print result
            boolean match = verifyPassword(username, inputPassword);
            System.out.println("Password Match:  " + match);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }

    // Generates a random 16-byte salt
    public static byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    // Hashes the password using SHA-256 with the given salt
    public static byte[] hashPassword(String password, byte[] salt) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt); // Add salt before hashing
        return md.digest(password.getBytes("UTF-8"));
    }

    // Checks if the password is in the breached list
    public static boolean isWeakPassword(String password) {
        return breached.contains(password.toLowerCase());
    }

    // Verifies the user's input password against the stored hash
    public static boolean verifyPassword(String username, String inputPassword) throws Exception {
        if (!userHashes.containsKey(username)) {
            System.out.println("[-] Username not found.");
            return false;
        }

        byte[] storedSalt = Base64.getDecoder().decode(userSalts.get(username));
        byte[] inputHash = hashPassword(inputPassword, storedSalt);
        String inputHashBase64 = Base64.getEncoder().encodeToString(inputHash);
        String storedHash = userHashes.get(username);

        // Debug prints (can be removed)
        System.out.println("[DEBUG] Stored Hash: " + storedHash);
        System.out.println("[DEBUG] Input  Hash:  " + inputHashBase64);

        return inputHashBase64.equals(storedHash);
    }

    public static String generateStrongPassword(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }
}