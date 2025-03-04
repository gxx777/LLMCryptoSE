import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESKeyReuse2 {

    private static final String ALGORITHM = "AES";

    public static String encrypt(String valueToEnc, String secretKey) throws NoSuchAlgorithmException, Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encryptedValue = cipher.doFinal(valueToEnc.getBytes());
        return Base64.getEncoder().encodeToString(encryptedValue);
    }

    public static String decrypt(String encryptedValue, String secretKey) throws NoSuchAlgorithmException, Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] originalValue = cipher.doFinal(Base64.getDecoder().decode(encryptedValue));
        return new String(originalValue);
    }

    public static void main(String[] args) {
        try {
            // Generate a secret key (in practice, this should be securely generated and stored)
            String secretKey = "ThisIsASecretKey"; // DO NOT DO THIS IN REAL WORLD SCENARIOS!

            // Participant 1 sends a message to Participant 2
            String messageFromParticipant1 = "Hello from Participant 1!";
            String encryptedMessage = encrypt(messageFromParticipant1, secretKey);
            System.out.println("Encrypted message: " + encryptedMessage);

            // Participant 2 receives the message and decrypts it
            String decryptedMessage = decrypt(encryptedMessage, secretKey);
            System.out.println("Decrypted message: " + decryptedMessage);

            // Participant 2 sends a message back to Participant 1
            String messageFromParticipant2 = "Hello from Participant 2!";
            encryptedMessage = encrypt(messageFromParticipant2, secretKey);
            System.out.println("Encrypted message: " + encryptedMessage);

            // Participant 1 receives the message and decrypts it
            decryptedMessage = decrypt(encryptedMessage, secretKey);
            System.out.println("Decrypted message: " + decryptedMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}