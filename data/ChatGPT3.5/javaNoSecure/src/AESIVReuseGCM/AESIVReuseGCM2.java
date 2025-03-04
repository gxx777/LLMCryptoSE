import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM2 {

    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private static final String AES_CIPHER_ALGORITHM = "AES/GCM/NoPadding";

    public static void main(String[] args) {
        try {
            // Generate random AES key
            byte[] keyBytes = new byte[16];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(keyBytes);
            SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

            // Generate random IV
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            // Initialize cipher for encryption
            Cipher encryptionCipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            encryptionCipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

            // Plain text message
            String message1 = "Message for participant 1";
            String message2 = "Message for participant 2";
            String message3 = "Message for participant 3";

            // Encrypt and send messages to participants
            byte[] cipherText1 = encryptionCipher.doFinal(message1.getBytes());
            byte[] cipherText2 = encryptionCipher.doFinal(message2.getBytes());
            byte[] cipherText3 = encryptionCipher.doFinal(message3.getBytes());

            // Print encrypted messages
            System.out.println("Encrypted message for participant 1: " + Base64.getEncoder().encodeToString(cipherText1));
            System.out.println("Encrypted message for participant 2: " + Base64.getEncoder().encodeToString(cipherText2));
            System.out.println("Encrypted message for participant 3: " + Base64.getEncoder().encodeToString(cipherText3));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}