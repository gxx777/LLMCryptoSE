import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

public class AESIVReuseOFB1 {

    // 静态的初始化向量（IV），实际应用中应该每次加密都使用新的IV
    private static final byte[] iv = "ThisIsAVeryBadIV".getBytes();

    // 密钥
    private static final byte[] key = "ThisIsASecretKey".getBytes();

    // 生成密钥
    private static Key generateKey() {
        return new SecretKeySpec(key, "AES");
    }

    // 加密方法
    public static String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, generateKey(), new IvParameterSpec(iv));
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 解密方法
    public static String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, generateKey(), new IvParameterSpec(iv));
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        // 消息1
        String message1 = "Hello, Party 1!";
        String encryptedMessage1 = encrypt(message1);
        String decryptedMessage1 = decrypt(encryptedMessage1);
        System.out.println("Message 1: " + message1);
        System.out.println("Encrypted Message 1: " + encryptedMessage1);
        System.out.println("Decrypted Message 1: " + decryptedMessage1);

        // 消息2
        String message2 = "Hello, Party 2!";
        String encryptedMessage2 = encrypt(message2);
        String decryptedMessage2 = decrypt(encryptedMessage2);
        System.out.println("Message 2: " + message2);
        System.out.println("Encrypted Message 2: " + encryptedMessage2);
        System.out.println("Decrypted Message 2: " + decryptedMessage2);

        // 消息3
        String message3 = "Hello, Party 3!";
        String encryptedMessage3 = encrypt(message3);
        String decryptedMessage3 = decrypt(encryptedMessage3);
        System.out.println("Message 3: " + message3);
        System.out.println("Encrypted Message 3: " + encryptedMessage3);
        System.out.println("Decrypted Message 3: " + decryptedMessage3);
    }
}