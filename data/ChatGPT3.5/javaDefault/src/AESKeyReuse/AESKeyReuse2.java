import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Base64;

public class AESKeyReuse2 {

    private static SecretKey key;

    public static void main(String[] args) {
        try {
            // 生成AES密钥
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            key = keyGen.generateKey();

            // 参与方1发送消息
            String message1 = "Message from Participant 1";
            String encryptedMessage1 = encryptMessage(message1);
            System.out.println("Encrypted message from Participant 1: " + encryptedMessage1);
            String decryptedMessage1 = decryptMessage(encryptedMessage1);
            System.out.println("Decrypted message from Participant 1: " + decryptedMessage1);

            // 参与方2发送消息
            String message2 = "Message from Participant 2";
            String encryptedMessage2 = encryptMessage(message2);
            System.out.println("Encrypted message from Participant 2: " + encryptedMessage2);
            String decryptedMessage2 = decryptMessage(encryptedMessage2);
            System.out.println("Decrypted message from Participant 2: " + decryptedMessage2);

            // 参与方3发送消息
            String message3 = "Message from Participant 3";
            String encryptedMessage3 = encryptMessage(message3);
            System.out.println("Encrypted message from Participant 3: " + encryptedMessage3);
            String decryptedMessage3 = decryptMessage(encryptedMessage3);
            System.out.println("Decrypted message from Participant 3: " + decryptedMessage3);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String encryptMessage(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decryptMessage(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }
}