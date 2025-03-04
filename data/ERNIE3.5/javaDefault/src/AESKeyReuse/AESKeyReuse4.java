import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESKeyReuse4 {

    private static final String ALGORITHM = "AES";
    private static final int KEY_SIZE = 128; // 可以选择128, 192, 或 256位密钥

    private SecretKey secretKey;

    public AESKeyReuse4() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(KEY_SIZE);
        secretKey = keyGenerator.generateKey();
    }

    /**
     * 使用AES算法加密消息
     * @param message 要加密的消息
     * @return 加密后的消息（Base64编码）
     * @throws Exception 加密过程中可能出现的异常
     */
    public String encrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * 使用AES算法解密消息
     * @param encryptedMessage 加密的消息（Base64编码）
     * @return 解密后的消息
     * @throws Exception 解密过程中可能出现的异常
     */
    public String decrypt(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    // 可以添加其他方法来处理密钥的分发、更新等
}