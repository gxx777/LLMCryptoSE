import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCFB4 {

    private static final String ALGORITHM = "AES/CFB/NoPadding";
    private SecretKey key;
    private IvParameterSpec iv;

    public AESIVReuseCFB4() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // Use 128-bit AES
        key = keyGenerator.generateKey();

        // Create a fixed IV for reuse
        byte[] ivBytes = new byte[16]; // AES block size for CFB mode is 16 bytes
        // Optionally, you can fill ivBytes with a specific value or use a secure random
        iv = new IvParameterSpec(ivBytes);
    }

    public String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            AESIVReuseCFB4 aes = new AESIVReuseCFB4();

            // Messages for three different parties
            String message1 = "Message for Party 1";
            String message2 = "Message for Party 2";
            String message3 = "Message for Party 3";

            // Encrypt messages
            String encrypted1 = aes.encrypt(message1);
            String encrypted2 = aes.encrypt(message2);
            String encrypted3 = aes.encrypt(message3);

            System.out.println("Encrypted Message 1: " + encrypted1);
            System.out.println("Encrypted Message 2: " + encrypted2);
            System.out.println("Encrypted Message 3: " + encrypted3);

            // Decrypt messages
            String decrypted1 = aes.decrypt(encrypted1);
            String decrypted2 = aes.decrypt(encrypted2);
            String decrypted3 = aes.decrypt(encrypted3);

            System.out.println("Decrypted Message 1: " + decrypted1);
            System.out.println("Decrypted Message 2: " + decrypted2);
            System.out.println("Decrypted Message 3: " + decrypted3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}