import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCBC1 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

    public String encrypt(String key, String plaintext) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16]; // AES with CBC Mode requires 16 bytes IV
        random.nextBytes(iv);

        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());

        // Combine the IV with the encrypted text using a colon
        return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String key, String encryptedText) throws Exception {
        String[] parts = encryptedText.split(":");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid input format. Expected IV followed by encrypted text.");
        }

        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] encryptedBytes = Base64.getDecoder().decode(parts[1]);

        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            AESIVReuseCBC1 aes = new AESIVReuseCBC1();

            // Encryption
            String key = "MySecretKey123"; // Use a strong and secure key in practice
            String plaintext = "Hello, World!";
            String encrypted = aes.encrypt(key, plaintext);
            System.out.println("Encrypted Text: " + encrypted);

            // Decryption
            String decrypted = aes.decrypt(key, encrypted);
            System.out.println("Decrypted Text: " + decrypted);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}