import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR4 {

    // AES密钥长度
    private static final int KEY_SIZE = 128;
    // AES IV长度（CTR模式）
    private static final int IV_SIZE = 16;

    /**
     * 使用AES的CTR模式加密消息
     *
     * @param message 要加密的消息
     * @param key     用于加密的密钥
     * @return 加密后的消息
     * @throws NoSuchAlgorithmException 如果密钥生成器不可用
     */
    public static String encryptMessage(String message, byte[] key) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        // 生成随机的IV
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[IV_SIZE];
        random.nextBytes(iv);

        // 创建AES Cipher实例
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        // 初始化Cipher
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));

        // 加密消息
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());

        // 返回Base64编码的加密消息和IV
        return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(encryptedMessage);
    }

    /**
     * 生成AES密钥
     *
     * @return AES密钥
     * @throws NoSuchAlgorithmException 如果密钥生成器不可用
     */
    public static byte[] generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey().getEncoded();
    }

    // 主函数，用于测试
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // 生成AES密钥
        byte[] key = generateKey();

        // 要加密的消息
        String message = "Hello, World!";

        // 加密消息
        String encryptedMessage = encryptMessage(message, key);

        // 输出加密后的消息
        System.out.println("Encrypted Message: " + encryptedMessage);
    }
}