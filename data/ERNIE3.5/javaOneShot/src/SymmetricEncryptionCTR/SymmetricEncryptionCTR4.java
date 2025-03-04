import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SymmetricEncryptionCTR4 {

    private static final String ALGORITHM = "AES/CTR/NoPadding";

    private SecretKey secretKey;
    private IvParameterSpec iv;

    public SymmetricEncryptionCTR4() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // 可以选择128, 192, 或 256位密钥
        secretKey = keyGenerator.generateKey();

        // CTR模式不需要初始化向量，但为了与Cipher接口保持一致，我们使用一个固定的值
        byte[] ivBytes = new byte[16]; // AES要求16字节的IV
        iv = new IvParameterSpec(ivBytes);
    }

    public String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        SymmetricEncryptionCTR4 encryptor = new SymmetricEncryptionCTR4();

        String originalText = "Hello, World!";
        String encryptedText = encryptor.encrypt(originalText);
        String decryptedText = encryptor.decrypt(encryptedText);

        System.out.println("Original Text: " + originalText);
        System.out.println("Encrypted Text: " + encryptedText);
        System.out.println("Decrypted Text: " + decryptedText);
    }
}