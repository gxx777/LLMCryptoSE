import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionCFB3 {

    private static final String ALGORITHM = "AES/CFB/NoPadding";
    private byte[] key;
    private byte[] iv;

    public SymmetricEncryptionCFB3(String secretKey) {
        this.key = secretKey.getBytes(StandardCharsets.UTF_8);
        this.iv = new byte[16]; // AES requires 16 byte IV for CFB mode
        new SecureRandom().nextBytes(this.iv);
    }

    public String encrypt(String valueToEncrypt) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(this.key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(this.iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encryptedValue = cipher.doFinal(valueToEncrypt.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedValue);
    }

    public String decrypt(String encryptedValue) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(this.key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(this.iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decryptedValue = cipher.doFinal(Base64.getDecoder().decode(encryptedValue));
        return new String(decryptedValue, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            String secretKey = "ThisIsASecretKey"; // 注意：实际应用中密钥需要安全生成并存储
            SymmetricEncryptionCFB3 encryptor = new SymmetricEncryptionCFB3(secretKey);

            String originalText = "This is a secret message.";
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