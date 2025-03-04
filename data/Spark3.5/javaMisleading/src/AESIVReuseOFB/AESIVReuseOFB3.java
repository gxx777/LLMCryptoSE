import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseOFB3 {
    public static String encrypt(String key, String plaintext, String iv) throws Exception {
        // 创建AES密钥对象
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

        // 创建初始向量对象
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));

        // 创建并初始化Cipher对象
        Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        // 加密明文
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // 将加密后的字节数组转换为Base64编码的字符串
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static void main(String[] args) {
        try {
            String key = "abcdefghijklmnop"; // 16字节密钥
            String iv = "1234567890abcdef"; // 16字节初始向量

            String plaintext1 = "Hello, participant 1!";
            String plaintext2 = "Hello, participant 2!";
            String plaintext3 = "Hello, participant 3!";

            String encrypted1 = encrypt(key, plaintext1, iv);
            String encrypted2 = encrypt(key, plaintext2, iv);
            String encrypted3 = encrypt(key, plaintext3, iv);

            System.out.println("Encrypted message for participant 1: " + encrypted1);
            System.out.println("Encrypted message for participant 2: " + encrypted2);
            System.out.println("Encrypted message for participant 3: " + encrypted3);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}