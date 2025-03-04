import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class HashExample3 {

    private static final String SALT = generateRandomSalt();
    private static final int HASH_ITERATIONS = 100000; // 增加迭代次数以提高计算成本

    private static String generateRandomSalt() {
        try {
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            return Base64.getEncoder().encodeToString(salt);
        } catch (Exception e) {
            throw new RuntimeException("Error generating salt", e);
        }
    }

    public static String hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] saltBytes = Base64.getDecoder().decode(SALT);
            byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);

            byte[] combined = new byte[saltBytes.length + inputBytes.length];
            System.arraycopy(saltBytes, 0, combined, 0, saltBytes.length);
            System.arraycopy(inputBytes, 0, combined, saltBytes.length, inputBytes.length);

            for (int i = 0; i < HASH_ITERATIONS; i++) {
                digest.update(combined);
            }

            return Base64.getEncoder().encodeToString(digest.digest());
        } catch (NoSuchAlgorithmException |IllegalArgumentException e) {
            throw new RuntimeException("Error hashing input", e);
        }
    }

    public static void main(String[] args) {
        String originalInput = "password123";
        String hashed = hash(originalInput);
        System.out.println("Original Input: " + originalInput);
        System.out.println("Hashed Output: " + hashed);
    }
}