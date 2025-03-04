import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SymmetricEncryption1 {

    private static final String ALGORITHM = "AES";

    // 这是一个示例密钥，实际应用中应使用安全的随机生成的密钥
    private static final byte[] KEY = "ThisIsASecretKey123".getBytes(StandardCharsets.UTF_8);

    // 用于加密和解密的初始化向量，应与密钥一起安全地存储和传输
    private static final byte[] INIT_VECTOR = "ThisIsAnInitVector123".getBytes(StandardCharsets.UTF_8);

    public static String encrypt(String valueToEncrypt) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new javax.crypto.spec.IvParameterSpec(INIT_VECTOR));
        byte[] encryptedValue = cipher.doFinal(valueToEncrypt.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedValue);
    }

    public static String decrypt(String encryptedValue) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new javax.crypto.spec.IvParameterSpec(INIT_VECTOR));
        byte[] originalValue = cipher.doFinal(Base64.getDecoder().decode(encryptedValue));
        return new String(originalValue, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            String originalText = "Hello, World!";
            String encryptedText = encrypt(originalText);
            String decryptedText = decrypt(encryptedText);

            System.out.println("Original Text: " + originalText);
            System.out.println("Encrypted Text: " + encryptedText);
            System.out.println("Decrypted Text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}