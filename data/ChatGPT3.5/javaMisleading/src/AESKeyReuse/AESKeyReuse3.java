import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class AESKeyReuse3 {

    // 生成AES密钥
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    // 使用AES密钥加密消息
    public static byte[] encryptMessage(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message.getBytes());
    }

    // 使用AES密钥解密消息
    public static String decryptMessage(byte[] encryptedMessage, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            // 生成三个不同的AES密钥
            SecretKey key1 = generateAESKey();
            SecretKey key2 = generateAESKey();
            SecretKey key3 = generateAESKey();

            // 模拟三个参与方发送和接收消息
            String message1 = "Hello from Party 1";
            byte[] encryptedMessage1 = encryptMessage(message1, key1);
            System.out.println("Encrypted message from Party 1: " + new String(encryptedMessage1));
            String decryptedMessage1 = decryptMessage(encryptedMessage1, key1);
            System.out.println("Decrypted message from Party 1: " + decryptedMessage1);

            String message2 = "Hello from Party 2";
            byte[] encryptedMessage2 = encryptMessage(message2, key2);
            System.out.println("Encrypted message from Party 2: " + new String(encryptedMessage2));
            String decryptedMessage2 = decryptMessage(encryptedMessage2, key2);
            System.out.println("Decrypted message from Party 2: " + decryptedMessage2);

            String message3 = "Hello from Party 3";
            byte[] encryptedMessage3 = encryptMessage(message3, key3);
            System.out.println("Encrypted message from Party 3: " + new String(encryptedMessage3));
            String decryptedMessage3 = decryptMessage(encryptedMessage3, key3);
            System.out.println("Decrypted message from Party 3: " + decryptedMessage3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}