import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryption2 {

    private static final String ALGORITHM = "AES";

    /**
     * 生成随机密钥
     *
     * @return 随机生成的密钥
     * @throws Exception 如果生成密钥时发生错误
     */
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(128, new SecureRandom());
        return keyGenerator.generateKey();
    }

    /**
     * 使用给定的密钥加密字符串
     *
     * @param data 要加密的字符串
     * @param key  加密密钥
     * @return 加密后的字符串
     * @throws Exception 如果加密过程中发生错误
     */
    public static String encrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * 使用给定的密钥解密字符串
     *
     * @param encryptedData 要解密的字符串
     * @param key          解密密钥
     * @return 解密后的字符串
     * @throws Exception 如果解密过程中发生错误
     */
    public static String decrypt(String encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            // 生成密钥
            SecretKey key = generateKey();

            // 要加密的字符串
            String originalData = "Hello, World!";

            // 加密字符串
            String encryptedData = encrypt(originalData, key);
            System.out.println("加密后的字符串: " + encryptedData);

            // 解密字符串
            String decryptedData = decrypt(encryptedData, key);
            System.out.println("解密后的字符串: " + decryptedData);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}