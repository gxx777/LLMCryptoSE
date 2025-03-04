import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCBC1 {
    public static void main(String[] args) throws Exception {
        // 生成密钥
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();

        // 生成初始向量
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // 加密消息
        String message1 = "Message from party 1";
        String message2 = "Message from party 2";
        String message3 = "Message from party 3";

        String encryptedMessage1 = encrypt(message1, secretKey, ivParameterSpec);
        String encryptedMessage2 = encrypt(message2, secretKey, ivParameterSpec);
        String encryptedMessage3 = encrypt(message3, secretKey, ivParameterSpec);

        System.out.println("Encrypted messages:");
        System.out.println("Party 1: " + encryptedMessage1);
        System.out.println("Party 2: " + encryptedMessage2);
        System.out.println("Party 3: " + encryptedMessage3);
    }

    public static String encrypt(String message, SecretKey secretKey, IvParameterSpec ivParameterSpec) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}