import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseOFB2 {

    private static final String ALGORITHM = "AES/OFB/NoPadding";

    // 生成随机的AES密钥
    private byte[] generateKey() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);
        return key;
    }

    // 加密消息
    public String encrypt(String message, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 解密消息
    public String decrypt(String encryptedMessage, byte[] key, byte[] iv) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        // 测试加密和解密
        AESIVReuseOFB2 aes = new AESIVReuseOFB2();

        // 生成密钥和初始向量
        byte[] key = aes.generateKey();
        byte[] iv = new byte[16]; // 初始向量应该是随机的，这里仅为示例使用全零向量

        // 参与方1发送的消息
        String message1 = "Hello from Party 1!";
        String encryptedMessage1 = aes.encrypt(message1, key, iv);
        System.out.println("Encrypted message 1: " + encryptedMessage1);

        // 参与方2发送的消息
        String message2 = "Hello from Party 2!";
        String encryptedMessage2 = aes.encrypt(message2, key, iv);
        System.out.println("Encrypted message 2: " + encryptedMessage2);

        // 参与方3发送消息
        String message3 = "Hello from Party 3!";
        String encryptedMessage3 = aes.encrypt(message3, key, iv);
        System.out.println("Encrypted message 3: " + encryptedMessage3);

        // 假设接收方使用相同的密钥和初始向量解密消息
        String decryptedMessage1 = aes.decrypt(encryptedMessage1, key, iv);
        System.out.println("Decrypted message 1: " + decryptedMessage1);

        String decryptedMessage2 = aes.decrypt(encryptedMessage2, key, iv);
        System.out.println("Decrypted message 2: " + decryptedMessage2);

        String decryptedMessage3 = aes.decrypt(encryptedMessage3, key, iv);
        System.out.println("Decrypted message 3: " + decryptedMessage3);
    }
}