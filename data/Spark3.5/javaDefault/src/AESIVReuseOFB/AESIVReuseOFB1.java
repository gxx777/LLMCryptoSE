import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESIVReuseOFB1 {

    public static void main(String[] args) throws Exception {
        // 生成密钥
        SecretKey secretKey = generateSecretKey();

        // 初始化向量
        byte[] iv = new byte[16];
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // 创建AES OFB模式的Cipher实例
        Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");

        // 第一个参与方的消息
        String message1 = "Hello, participant 1!";
        String encryptedMessage1 = encrypt(cipher, secretKey, ivParameterSpec, message1);
        System.out.println("Encrypted message for participant 1: " + encryptedMessage1);

        // 第二个参与方的消息
        String message2 = "Hello, participant 2!";
        String encryptedMessage2 = encrypt(cipher, secretKey, ivParameterSpec, message2);
        System.out.println("Encrypted message for participant 2: " + encryptedMessage2);

        // 第三个参与方的消息
        String message3 = "Hello, participant 3!";
        String encryptedMessage3 = encrypt(cipher, secretKey, ivParameterSpec, message3);
        System.out.println("Encrypted message for participant 3: " + encryptedMessage3);
    }

    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private static String encrypt(Cipher cipher, SecretKey secretKey, IvParameterSpec ivParameterSpec, String message) throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}