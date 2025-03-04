import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

public class AESIVReuseOFB4 {

    // AES密钥
    private static final byte[] KEY = "ThisIsASecretKeyThisIsASecretKey".getBytes();

    // 初始化向量（IV），不应该重复使用，但为了满足题目要求，这里我们重复使用
    private static final byte[] IV = "ThisIsAnIV".getBytes();

    // AES加密算法名称
    private static final String ALGORITHM = "AES/OFB/NoPadding";

    // 加密方法
    public static String encrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        Key key = new SecretKeySpec(KEY, "AES");
        IvParameterSpec iv = new IvParameterSpec(IV);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 解密方法
    public static String decrypt(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        Key key = new SecretKeySpec(KEY, "AES");
        IvParameterSpec iv = new IvParameterSpec(IV);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        byte[] decodedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    // 测试加密和解密方法
    public static void main(String[] args) {
        try {
            // 发送方A的消息
            String messageA = "Hello from A";
            String encryptedA = encrypt(messageA);
            System.out.println("Encrypted A: " + encryptedA);

            // 发送方B消息
            String messageB = "Hello from B";
            String encryptedB = encrypt(messageB);
            System.out.println("Encrypted B: " + encryptedB);

            // 发送方C消息
            String messageC = "Hello from C";
            String encryptedC = encrypt(messageC);
            System.out.println("Encrypted C: " + encryptedC);

            // 接收方解密消息
            String decryptedA = decrypt(encryptedA);
            System.out.println("Decrypted A: " + decryptedA);

            String decryptedB = decrypt(encryptedB);
            System.out.println("Decrypted B: " + decryptedB);

            String decryptedC = decrypt(encryptedC);
            System.out.println("Decrypted C: " + decryptedC);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}