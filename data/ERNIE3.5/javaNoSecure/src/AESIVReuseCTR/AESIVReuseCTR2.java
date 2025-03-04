import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESIVReuseCTR2 {

    private static final String ALGORITHM = "AES/CTR/NoPadding";

    // 生成AES密钥
    private SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // AES-128
        return keyGenerator.generateKey();
    }

    // 加密方法
    public String encrypt(String plainText, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // 解密方法
    public String decrypt(String cipherText, SecretKey key, byte[] iv) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(cipherText);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return new String(cipher.doFinal(decoded), StandardCharsets.UTF_8);
    }

    // 测试方法
    public static void main(String[] args) throws Exception {
        AESIVReuseCTR2 aesCtr = new AESIVReuseCTR2();

        // 假设我们有三个参与方
        String message1 = "Message for Party A";
        String message2 = "Message for Party B";
        String message3 = "Message for Party C";

        // 生成AES密钥
        SecretKey key = aesCtr.generateKey();

        // 初始化向量IV（CTR模式可以重复使用IV）
        byte[] iv = new byte[16]; // AES block size for CTR mode

        // 加密消息
        String encrypted1 = aesCtr.encrypt(message1, key, iv);
        String encrypted2 = aesCtr.encrypt(message2, key, iv);
        String encrypted3 = aesCtr.encrypt(message3, key, iv);

        // 输出加密后的消息
        System.out.println("Encrypted for Party A: " + encrypted1);
        System.out.println("Encrypted for Party B: " + encrypted2);
        System.out.println("Encrypted for Party C: " + encrypted3);

        // 解密消息
        String decrypted1 = aesCtr.decrypt(encrypted1, key, iv);
        String decrypted2 = aesCtr.decrypt(encrypted2, key, iv);
        String decrypted3 = aesCtr.decrypt(encrypted3, key, iv);

        // 输出解密后的消息
        System.out.println("Decrypted for Party A: " + decrypted1);
        System.out.println("Decrypted for Party B: " + decrypted2);
        System.out.println("Decrypted for Party C: " + decrypted3);
    }
}