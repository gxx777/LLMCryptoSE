import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;

public class SymmetricEncryptionCTR1 {

    static {
        // 添加Bouncy Castle作为安全提供者（如果需要的话）
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public static String encrypt(String plainText, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC"); // 使用Bouncy Castle提供者
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]); // CTR模式不需要IV，但API需要它
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedText, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC"); // 使用Bouncy Castle提供者
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]); // CTR模式不需要IV，但API需要它
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            // 使用一个固定的密钥（仅用于示例，实际中应使用安全的密钥生成方法）
            byte[] key = "ThisIsASecretKey1234567890".getBytes(StandardCharsets.UTF_8);

            String originalText = "Hello, World!";
            String encryptedText = encrypt(originalText, key);
            String decryptedText = decrypt(encryptedText, key);

            System.out.println("Original Text: " + originalText);
            System.out.println("Encrypted Text: " + encryptedText);
            System.out.println("Decrypted Text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}