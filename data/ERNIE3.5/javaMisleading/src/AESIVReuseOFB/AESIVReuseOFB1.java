import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseOFB1 {

    // 密钥长度
    private static final int KEY_SIZE = 128;
    // 初始化向量长度
    private static final int IV_SIZE = 16;

    public static void main(String[] args) throws Exception {
        // 创建AES密钥
        SecretKey secretKey = generateKey(KEY_SIZE);

        // 初始化向量（IV），我们将重用此IV
        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // 消息和接收方
        String[] messages = {"Message 1", "Message 2", "Message 3"};
        String[] receivers = {"Receiver 1", "Receiver 2", "Receiver 3"};

        // 加密每个消息
        for (int i = 0; i < messages.length; i++) {
            String message = messages[i];
            byte[] encrypted = encrypt(message.getBytes(StandardCharsets.UTF_8), secretKey, iv);

            // 发送加密消息给对应的接收方
            sendEncryptedMessage(encrypted, receivers[i]);
        }
    }

    private static SecretKey generateKey(int keySize) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    private static byte[] encrypt(byte[] message, SecretKey secretKey, byte[] iv) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        return cipher.doFinal(message);
    }

    private static void sendEncryptedMessage(byte[] encryptedMessage, String receiver) {
        // 这里应该添加代码来发送加密的消息给指定的接收者
        // 例如，可以通过网络发送、保存到文件或数据库等
        System.out.println("Sending encrypted message to " + receiver + ": " + Base64.getEncoder().encodeToString(encryptedMessage));
    }
}