import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCBC3 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 128; // AES-128
    private static final SecureRandom random = new SecureRandom();

    public static void main(String[] args) {
        try {
            // 模拟三个参与方的消息
            String message1 = "Message from Participant 1";
            String message2 = "Message from Participant 2";
            String message3 = "Message from Participant 3";

            // 生成密钥
            byte[] key = generateRandomKey();

            // 加密三个消息
            String encryptedMessage1 = encrypt(message1, key);
            String encryptedMessage2 = encrypt(message2, key);
            String encryptedMessage3 = encrypt(message3, key);

            // 输出加密后的消息
            System.out.println("Encrypted Message 1: " + encryptedMessage1);
            System.out.println("Encrypted Message 2: " + encryptedMessage2);
            System.out.println("Encrypted Message 3: " + encryptedMessage3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] generateRandomKey() {
        byte[] key = new byte[KEY_SIZE / 8];
        random.nextBytes(key);
        return key;
    }

    private static String encrypt(String message, byte[] key) throws Exception {
        // 生成随机的IV
        byte[] iv = new byte[16];
        random.nextBytes(iv);

        // 创建Cipher实例
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // 初始化Cipher为加密模式
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        // 执行加密操作
        byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        // 返回Base64编码的加密消息
        return Base64.getEncoder().encodeToString(iv).concat(":").concat(Base64.getEncoder().encodeToString(encrypted));
    }
}