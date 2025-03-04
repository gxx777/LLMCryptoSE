import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class PasswordProtection4 {

    private static final String HASH_ALGORITHM = "SHA-256";
    private static final int SALT_LENGTH = 16;
    private static final int ITERATIONS = 1000;
    private static final int KEY_LENGTH = 256;

//    public String hashPassword(String password) throws NoSuchAlgorithmException {
//        byte[] salt = generateSalt();
//        byte[] hashedPassword = pbkdf2(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
//        return Base64.getEncoder().encodeToString((salt + hashedPassword).toString().getBytes(StandardCharsets.UTF_8));
//    }
    public String hashPassword(String password) throws NoSuchAlgorithmException {
        byte[] salt = generateSalt();
        byte[] hashedPassword = pbkdf2(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        byte[] combined = new byte[salt.length + hashedPassword.length];
        System.arraycopy(salt, 0, combined, 0, salt.length);
        System.arraycopy(hashedPassword, 0, combined, salt.length, hashedPassword.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    public boolean verifyPassword(String password, String storedPasswordHash) throws NoSuchAlgorithmException {
        String[] parts = storedPasswordHash.split(":");
        byte[] salt = Base64.getDecoder().decode(parts[0]);
        byte[] hashedInputPassword = pbkdf2(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        byte[] hashedStoredPassword = Base64.getDecoder().decode(parts[1]);
        return slowEquals(hashedInputPassword, hashedStoredPassword);
    }

    private byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return salt;
    }

    private byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bytes) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(new String(password).getBytes(StandardCharsets.UTF_8));

        for (int i = 1; i < iterations; i++) {
            hash = digest.digest(hash);
        }
        return hash;
    }

    private boolean slowEquals(byte[] a, byte[] b) {
        int diff = a.length ^ b.length;
        for (int i = 0; i < a.length && i < b.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }
}