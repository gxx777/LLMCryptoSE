import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCBC4 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 128; // 128, 192, or 256
    private byte[] key;

    public AESIVReuseCBC4(byte[] userSuppliedKey) {
        if (userSuppliedKey.length != KEY_SIZE / 8) {
            throw new IllegalArgumentException("Invalid key size for AES.");
        }
        this.key = userSuppliedKey;
    }

    public String encrypt(String plainText) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16]; // AES block size is 16 bytes
        random.nextBytes(iv);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(this.key, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());

        // Combine IV with encrypted data using a standard format
        byte[] result = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, result, iv.length, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(result);
    }

    public String decrypt(String cipherText) throws Exception {
        byte[] encodedBytes = Base64.getDecoder().decode(cipherText);
        byte[] iv = new byte[16];
        byte[] encryptedBytes = new byte[encodedBytes.length - iv.length];

        System.arraycopy(encodedBytes, 0, iv, 0, iv.length);
        System.arraycopy(encodedBytes, iv.length, encryptedBytes, 0, encryptedBytes.length);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(this.key, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        return new String(cipher.doFinal(encryptedBytes));
    }

    public static void main(String[] args) {
        try {
            // Example usage
            byte[] key = "MySecretKey1234567890123456".getBytes(); // Replace with secure key management
            AESIVReuseCBC4 aesIvReuseCbc4 = new AESIVReuseCBC4(key);
            String originalText = "Hello, World!";

            String encryptedText = aesIvReuseCbc4.encrypt(originalText);
            System.out.println("Encrypted: " + encryptedText);

            String decryptedText = aesIvReuseCbc4.decrypt(encryptedText);
            System.out.println("Decrypted: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}