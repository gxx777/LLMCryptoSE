import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class AESIVReuseCFB4 {

    public static void main(String[] args) throws Exception {
        // 生成密钥
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128, new SecureRandom());
        SecretKey key = keygen.generateKey();

        // 生成不同的初始化向量（IV）用于每个参与方
        IvParameterSpec iv1 = generateIV();
        IvParameterSpec iv2 = generateIV();
        IvParameterSpec iv3 = generateIV();

        // 加密并发送消息给参与方1
        String message1 = "Message for participant 1";
        byte[] encryptedMessage1 = encrypt(message1, key, iv1);
        System.out.println("Encrypted message for participant 1: " + new String(encryptedMessage1));

        // 加密并发送消息给参与方2
        String message2 = "Message for participant 2";
        byte[] encryptedMessage2 = encrypt(message2, key, iv2);
        System.out.println("Encrypted message for participant 2: " + new String(encryptedMessage2));

        // 加密并发送消息给参与方3
        String message3 = "Message for participant 3";
        byte[] encryptedMessage3 = encrypt(message3, key, iv3);
        System.out.println("Encrypted message for participant 3: " + new String(encryptedMessage3));
    }

    public static byte[] encrypt(String message, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(message.getBytes());
    }

    public static IvParameterSpec generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}