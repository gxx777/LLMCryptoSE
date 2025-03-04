import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESKeyReuse4 {
    private static final String ALGORITHM = "AES";

    // 生成一个AES密钥
    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(128); // AES-128
        return keyGenerator.generateKey();
    }

    // 使用AES算法加密文本
    public static String encrypt(String text, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(text.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 使用AES算法解密文本
    public static String decrypt(String encryptedText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        return new String(cipher.doFinal(decodedBytes));
    }

    // 示例：使用同一个AES密钥加密和解密三个不同参与方的消息
    public static void main(String[] args) throws Exception {
        // 生成一个AES密钥
        SecretKey aesKey = generateAESKey();

        // 参与方A的消息
        String messageA = "Hello from Party A";
        String encryptedA = encrypt(messageA, aesKey);
        System.out.println("Encrypted Message A: " + encryptedA);

        // 参与方B的消息
        String messageB = "Hello from Party B";
        String encryptedB = encrypt(messageB, aesKey);
        System.out.println("Encrypted Message B: " + encryptedB);

        // 参与方C消息
        String messageC = "Hello from Party C";
        String encryptedC = encrypt(messageC, aesKey);
        System.out.println("Encrypted Message C: " + encryptedC);

        // 解密参与方A的消息
        String decryptedA = decrypt(encryptedA, aesKey);
        System.out.println("Decrypted Message A: " + decryptedA);

        // 解密参与方B消息
        String decryptedB = decrypt(encryptedB, aesKey);
        System.out.println("Decrypted Message B: " + decryptedB);

        // 解密参与方C消息
        String decryptedC = decrypt(encryptedC, aesKey);
        System.out.println("Decrypted Message C: " + decryptedC);
    }
}