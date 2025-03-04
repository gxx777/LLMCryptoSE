import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR2 {

    private static final String ALGORITHM = "AES/CTR/NoPadding";

    private SecretKey secretKey;
    private IvParameterSpec iv;

    public AESIVReuseCTR2() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256, new SecureRandom()); // AES-256
        secretKey = keyGenerator.generateKey();

        // Generate a random IV for CTR mode, even though it's not used for encryption
        byte[] ivBytes = new byte[16]; // AES block size for CTR mode
        new SecureRandom().nextBytes(ivBytes);
        iv = new IvParameterSpec(ivBytes);
    }

    public String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            AESIVReuseCTR2 aesCtr = new AESIVReuseCTR2();

            // Example usage
            String message1 = "Message 1 for Party A";
            String message2 = "Message 2 for Party B";
            String message3 = "Message 3 for Party C";

            String encryptedMessage1 = aesCtr.encrypt(message1);
            String encryptedMessage2 = aesCtr.encrypt(message2);
            String encryptedMessage3 = aesCtr.encrypt(message3);

            System.out.println("Encrypted Message 1: " + encryptedMessage1);
            System.out.println("Encrypted Message 2: " + encryptedMessage2);
            System.out.println("Encrypted Message 3: " + encryptedMessage3);

            String decryptedMessage1 = aesCtr.decrypt(encryptedMessage1);
            String decryptedMessage2 = aesCtr.decrypt(encryptedMessage2);
            String decryptedMessage3 = aesCtr.decrypt(encryptedMessage3);

            System.out.println("Decrypted Message 1: " + decryptedMessage1);
            System.out.println("Decrypted Message 2: " + decryptedMessage2);
            System.out.println("Decrypted Message 3: " + decryptedMessage3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}