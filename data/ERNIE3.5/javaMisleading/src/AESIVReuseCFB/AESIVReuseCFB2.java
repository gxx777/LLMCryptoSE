import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCFB2 {

    private static final String ALGORITHM = "AES/CFB/NoPadding";
    private static final int KEY_SIZE = 128;

    private SecretKey secretKey;
    private IvParameterSpec iv;

    public AESIVReuseCFB2() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        secretKey = keyGenerator.generateKey();

        // Note: In a real-world scenario, the IV should be unique and unpredictable for each encryption.
        // Reusing the IV across encryptions compromises security.
        byte[] ivBytes = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);
        iv = new IvParameterSpec(ivBytes);
    }

    public String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes, "UTF-8");
    }

    public static void main(String[] args) {
        try {
            AESIVReuseCFB2 aesCfb = new AESIVReuseCFB2();

            // Party A sends an encrypted message to Party B
            String messageFromA = "Hello from Party A!";
            String encryptedMessageFromA = aesCfb.encrypt(messageFromA);
            System.out.println("Encrypted message from A: " + encryptedMessageFromA);

            // Party B receives and decrypts the message from Party A
            String decryptedMessageFromA = aesCfb.decrypt(encryptedMessageFromA);
            System.out.println("Decrypted message from A: " + decryptedMessageFromA);

            // Party B sends an encrypted message to Party C
            String messageFromB = "Hello from Party B!";
            String encryptedMessageFromB = aesCfb.encrypt(messageFromB);
            System.out.println("Encrypted message from B: " + encryptedMessageFromB);

            // Party C receives and decrypts the message from Party B
            String decryptedMessageFromB = aesCfb.decrypt(encryptedMessageFromB);
            System.out.println("Decrypted message from B: " + decryptedMessageFromB);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}