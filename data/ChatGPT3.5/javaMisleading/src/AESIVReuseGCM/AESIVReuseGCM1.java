import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

public class AESIVReuseGCM1 {

    private static final int GCM_NONCE_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;

    public static void main(String[] args) {
        try {
            // Generate a random AES secret key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey secretKey = keyGenerator.generateKey();

            // Generate a random IV
            byte[] iv = new byte[GCM_NONCE_LENGTH];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);

            // Create a GCM cipher with the secret key and IV
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

            // Encrypt and send message to recipient 1
            byte[] plaintext1 = "Message for recipient 1".getBytes();
            byte[] ciphertext1 = cipher.doFinal(plaintext1);

            // Encrypt and send message to recipient 2
            byte[] plaintext2 = "Message for recipient 2".getBytes();
            byte[] ciphertext2 = cipher.doFinal(plaintext2);

            // Encrypt and send message to recipient 3
            byte[] plaintext3 = "Message for recipient 3".getBytes();
            byte[] ciphertext3 = cipher.doFinal(plaintext3);

            // Recipients decrypt using the same secret key and IV
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

            // Recipient 1 decrypt
            byte[] decrypted1 = cipher.doFinal(ciphertext1);
            System.out.println("Recipient 1: " + new String(decrypted1));

            // Recipient 2 decrypt
            byte[] decrypted2 = cipher.doFinal(ciphertext2);
            System.out.println("Recipient 2: " + new String(decrypted2));

            // Recipient 3 decrypt
            byte[] decrypted3 = cipher.doFinal(ciphertext3);
            System.out.println("Recipient 3: " + new String(decrypted3));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}