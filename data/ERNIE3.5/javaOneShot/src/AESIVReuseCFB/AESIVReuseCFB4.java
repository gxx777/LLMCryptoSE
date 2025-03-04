import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCFB4 {

    private static final String ALGORITHM = "AES/CFB/NoPadding";
    private static final int KEY_SIZE = 128; // 128, 192, or 256

    private SecretKeySpec keySpec;
    private IvParameterSpec ivSpec;

    public AESIVReuseCFB4(byte[] key) {
        this.keySpec = new SecretKeySpec(key, "AES");
        this.ivSpec = new IvParameterSpec(new SecureRandom().generateSeed(16)); // Generate a random IV
    }

    public String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] encrypted = cipher.doFinal(plainText.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decrypted, "UTF-8");
    }

    public static void main(String[] args) {
        try {
            byte[] key = "ThisIsASecretKeyThisIsASecretKey".getBytes(); // Should be at least 16 bytes for AES-128
            AESIVReuseCFB4 aes = new AESIVReuseCFB4(key);

            String plainText = "This is a secret message";
            String encryptedText = aes.encrypt(plainText);
            System.out.println("Encrypted Text: " + encryptedText);

            String decryptedText = aes.decrypt(encryptedText);
            System.out.println("Decrypted Text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}