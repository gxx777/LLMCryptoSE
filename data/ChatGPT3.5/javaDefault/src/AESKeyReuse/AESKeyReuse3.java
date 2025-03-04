import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AESKeyReuse3 {

    private static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private static byte[] encrypt(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message.getBytes());
    }

    private static String decrypt(byte[] cipherText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(cipherText);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            // Generate AES key
            SecretKey key = generateAESKey();

            // Participant 1
            String message1 = "Hello from Participant 1";
            byte[] cipherText1 = encrypt(message1, key);
            System.out.println("Participant 1 sent: " + new String(cipherText1));

            // Participant 2
            String message2 = "Greetings from Participant 2";
            byte[] cipherText2 = encrypt(message2, key);
            System.out.println("Participant 2 sent: " + new String(cipherText2));

            // Participant 3
            String message3 = "Howdy from Participant 3";
            byte[] cipherText3 = encrypt(message3, key);
            System.out.println("Participant 3 sent: " + new String(cipherText3));

            // Participant 1 receives message
            String decryptedMessage1 = decrypt(cipherText1, key);
            System.out.println("Participant 1 received: " + decryptedMessage1);

            // Participant 2 receives message
            String decryptedMessage2 = decrypt(cipherText2, key);
            System.out.println("Participant 2 received: " + decryptedMessage2);

            // Participant 3 receives message
            String decryptedMessage3 = decrypt(cipherText3, key);
            System.out.println("Participant 3 received: " + decryptedMessage3);

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

}