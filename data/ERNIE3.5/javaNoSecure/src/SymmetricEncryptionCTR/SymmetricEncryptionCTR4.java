import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SymmetricEncryptionCTR4 {

    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final String KEY_SPEC = "AES";

    // 注意：这里为了简单起见，我使用了固定的密钥和初始向量。
    // 在实际应用中，您应该使用安全的随机生成器来生成这些值，并妥善保管它们。
    private static final byte[] KEY = "ThisIsASecretKey12345678".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "ThisIsAnIv12345678".getBytes(StandardCharsets.UTF_8);

    public static String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, KEY_SPEC);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // 返回Base64编码的加密文本
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, KEY_SPEC);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));

        // 返回解密后的文本
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            String originalText = "This is a secret message.";
            System.out.println("Original Text: " + originalText);

            // 加密文本
            String encryptedText = encrypt(originalText);
            System.out.println("Encrypted Text: " + encryptedText);

            // 解密文本
            String decryptedText = decrypt(encryptedText);
            System.out.println("Decrypted Text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}