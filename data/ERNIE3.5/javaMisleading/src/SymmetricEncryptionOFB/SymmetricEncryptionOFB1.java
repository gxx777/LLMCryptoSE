import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;

public class SymmetricEncryptionOFB1 {

    // 初始化Bouncy Castle提供者
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String ALGORITHM = "AES/OFB/NoPadding";

    public static String encrypt(String key, String data) throws Exception {
        // 初始化密钥和初始化向量
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        byte[] ivBytes = new byte[16]; // AES要求16字节的初始化向量
        
        // 创建AES密钥和初始化向量规范
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        // 创建Cipher实例
        Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

        // 加密数据
        byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

        // 返回Base64编码的加密字符串
        return new String(java.util.Base64.getEncoder().encode(encryptedData), StandardCharsets.UTF_8);
    }

    public static String decrypt(String key, String encryptedData) throws Exception {
        // 解码Base64编码的加密字符串
        byte[] encryptedBytes = java.util.Base64.getDecoder().decode(encryptedData.getBytes(StandardCharsets.UTF_8));

        // 初始化密钥和初始化向量
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        byte[] ivBytes = new byte[16]; // AES要求16字节的初始化向量

        // 创建AES密钥和初始化向量规范
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        // 创建Cipher实例
        Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

        // 解密数据
        byte[] decryptedData = cipher.doFinal(encryptedBytes);

        // 返回解密后的字符串
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            String key = "ThisIsASecretKey"; // 密钥，应该是安全的
            String data = "Hello, World!"; // 要加密的数据

            // 加密数据
            String encryptedData = encrypt(key, data);
            System.out.println("Encrypted: " + encryptedData);

            // 解密数据
            String decryptedData = decrypt(key, encryptedData);
            System.out.println("Decrypted: " + decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}