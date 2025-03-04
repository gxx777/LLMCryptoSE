import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryption4 {

    private static final String ALGORITHM = "AES";

    // 生成密钥
    private SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(128, new SecureRandom());
        return keyGenerator.generateKey();
    }

    // 加密
    public String encrypt(String plainText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 解密
    public String decrypt(String encryptedText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        return new String(cipher.doFinal(decodedBytes), StandardCharsets.UTF_8);
    }

    // 示例使用
    public static void main(String[] args) throws Exception {
        SymmetricEncryption4 symmetricEncryption = new SymmetricEncryption4();

        // 生成密钥
        SecretKey secretKey = symmetricEncryption.generateKey();

        // 加密
        String plainText = "Hello, World!";
        String encryptedText = symmetricEncryption.encrypt(plainText, secretKey);
        System.out.println("Encrypted Text: " + encryptedText);

        // 解密
        String decryptedText = symmetricEncryption.decrypt(encryptedText, secretKey);
        System.out.println("Decrypted Text: " + decryptedText);
    }
}