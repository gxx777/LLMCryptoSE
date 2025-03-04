import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionOFB4 {

    private static final String ALGORITHM = "AES/OFB/PKCS5Padding";

    // 生成密钥和初始化向量
    public static String generateKeyAndIV() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128, new SecureRandom()); // 使用128位密钥
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] iv = new byte[16]; // AES要求16字节的IV
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // 返回Base64编码的密钥和IV，用冒号分隔
        return Base64.getEncoder().encodeToString(secretKey.getEncoded()) + ":" + Base64.getEncoder().encodeToString(iv);
    }

    // 加密方法
    public static String encrypt(String data, String keyAndIV) throws Exception {
        String[] keyAndIvParts = keyAndIV.split(":");
        byte[] keyBytes = Base64.getDecoder().decode(keyAndIvParts[0]);
        byte[] ivBytes = Base64.getDecoder().decode(keyAndIvParts[1]);

        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    // 解密方法
    public static String decrypt(String encryptedData, String keyAndIV) throws Exception {
        String[] keyAndIvParts = keyAndIV.split(":");
        byte[] keyBytes = Base64.getDecoder().decode(keyAndIvParts[0]);
        byte[] ivBytes = Base64.getDecoder().decode(keyAndIvParts[1]);

        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedData)), StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            // 生成密钥和IV
            String keyAndIV = generateKeyAndIV();
            System.out.println("Generated Key and IV: " + keyAndIV);

            // 加密数据
            String data = "This is a secret message.";
            String encrypted = encrypt(data, keyAndIV);
            System.out.println("Encrypted: " + encrypted);

            // 解密数据
            String decrypted = decrypt(encrypted, keyAndIV);
            System.out.println("Decrypted: " + decrypted);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}