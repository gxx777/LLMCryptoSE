import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class AESIVReuseCFB4 {
    
    private static SecretKey secretKey;
    private static IvParameterSpec iv;

    public static void generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        secretKey = keyGenerator.generateKey();
    }

    public static byte[] encryptMessage(byte[] message, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        return cipher.doFinal(message);
    }

    public static byte[] decryptMessage(byte[] encryptedMessage, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        return cipher.doFinal(encryptedMessage);
    }

    public static void main(String[] args) {
        try {
            generateKey();
            byte[] message1 = "Hello, participant 1!".getBytes();
            byte[] message2 = "Hello, participant 2!".getBytes();
            byte[] message3 = "Hello, participant 3!".getBytes();

            SecureRandom random = new SecureRandom();
            byte[] ivBytes = new byte[16];
            random.nextBytes(ivBytes);
            iv = new IvParameterSpec(ivBytes);

            byte[] encryptedMessage1 = encryptMessage(message1, iv);
            byte[] encryptedMessage2 = encryptMessage(message2, iv);
            byte[] encryptedMessage3 = encryptMessage(message3, iv);

            byte[] decryptedMessage1 = decryptMessage(encryptedMessage1, iv);
            byte[] decryptedMessage2 = decryptMessage(encryptedMessage2, iv);
            byte[] decryptedMessage3 = decryptMessage(encryptedMessage3, iv);

            System.out.println("Decrypted message 1: " + new String(decryptedMessage1));
            System.out.println("Decrypted message 2: " + new String(decryptedMessage2));
            System.out.println("Decrypted message 3: " + new String(decryptedMessage3));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}