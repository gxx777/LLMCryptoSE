import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESIVReuseCTR3 {
    
    private static final String key = "abcdefghijklmnop"; // 128-bit secret key
    private static final String iv = "1234567890123456"; // 16-byte initial vector

    // Encrypt message using AES CTR mode
    public static byte[] encrypt(String message, String key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            return cipher.doFinal(message.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // Decrypt message using AES CTR mode
    public static String decrypt(byte[] encryptedMessage, String key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            return new String(cipher.doFinal(encryptedMessage));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        String message1 = "Message for Participant 1";
        String message2 = "Message for Participant 2";
        String message3 = "Message for Participant 3";

        // Encrypt and send messages to three participants
        byte[] encryptedMessage1 = encrypt(message1, key);
        byte[] encryptedMessage2 = encrypt(message2, key);
        byte[] encryptedMessage3 = encrypt(message3, key);

        // Decrypt and read messages from three participants
        String decryptedMessage1 = decrypt(encryptedMessage1, key);
        String decryptedMessage2 = decrypt(encryptedMessage2, key);
        String decryptedMessage3 = decrypt(encryptedMessage3, key);

        System.out.println("Decrypted Message for Participant 1: " + decryptedMessage1);
        System.out.println("Decrypted Message for Participant 2: " + decryptedMessage2);
        System.out.println("Decrypted Message for Participant 3: " + decryptedMessage3);
    }
}