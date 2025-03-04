import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SymmetricEncryptionOFB3 {

    private static final String ALGORITHM = "AES/OFB/NoPadding";
    private static final String KEY_SPEC = "AES";
    private byte[] key;
    private byte[] iv;

    public SymmetricEncryptionOFB3(byte[] key, byte[] iv) {
        this.key = key;
        this.iv = iv;
    }

    public String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, KEY_SPEC);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public String decrypt(String encryptedData) throws Exception {
        byte[] cipherText = Base64.getDecoder().decode(encryptedData);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, KEY_SPEC);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] decryptedData = cipher.doFinal(cipherText);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            // 16 bytes key and 16 bytes IV are recommended for AES
            byte[] key = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
            byte[] iv = "fedcba9876543210".getBytes(StandardCharsets.UTF_8);

            SymmetricEncryptionOFB3 encryptor = new SymmetricEncryptionOFB3(key, iv);

            String originalText = "Hello, this is a test!";
            String encryptedText = encryptor.encrypt(originalText);
            String decryptedText = encryptor.decrypt(encryptedText);

            System.out.println("Original Text: " + originalText);
            System.out.println("Encrypted Text: " + encryptedText);
            System.out.println("Decrypted Text: " + decryptedText);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}