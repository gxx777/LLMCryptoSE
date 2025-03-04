import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESIVReuseOFB1 {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "OFB";
    private static final String PADDING = "PKCS5Padding";

    private static final byte[] IV = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    private static final byte[] KEY = { 0x2B, 0x7E, 0x15, 0x16, 0x28, (byte) 0xAE, (byte) 0xD2, (byte) 0xA6, (byte) 0xAB, (byte) 0xF7, 0x15, (byte) 0x88, 0x09, (byte) 0xCF, 0x4F, 0x3C };

    public static byte[] encrypt(String plainText, byte[] iv, byte[] key) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
            SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            return cipher.doFinal(plainText.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(byte[] cipherText, byte[] iv, byte[] key) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
            SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            return new String(cipher.doFinal(cipherText));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        // Encrypt message for participant 1
        String message1 = "Hello from participant 1";
        byte[] encryptedMessage1 = encrypt(message1, IV, KEY);
        System.out.println("Encrypted message for participant 1: " + new String(encryptedMessage1));

        // Decrypt message for participant 1
        String decryptedMessage1 = decrypt(encryptedMessage1, IV, KEY);
        System.out.println("Decrypted message for participant 1: " + decryptedMessage1);

        // Encrypt message for participant 2
        String message2 = "Hello from participant 2";
        byte[] encryptedMessage2 = encrypt(message2, IV, KEY);
        System.out.println("Encrypted message for participant 2: " + new String(encryptedMessage2));

        // Decrypt message for participant 2
        String decryptedMessage2 = decrypt(encryptedMessage2, IV, KEY);
        System.out.println("Decrypted message for participant 2: " + decryptedMessage2);

        // Encrypt message for participant 3
        String message3 = "Hello from participant 3";
        byte[] encryptedMessage3 = encrypt(message3, IV, KEY);
        System.out.println("Encrypted message for participant 3: " + new String(encryptedMessage3));

        // Decrypt message for participant 3
        String decryptedMessage3 = decrypt(encryptedMessage3, IV, KEY);
        System.out.println("Decrypted message for participant 3: " + decryptedMessage3);
    }
}