import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseOFB3 {
    private static final String ALGORITHM = "AES";
    private static final String MODE = "OFB";
    private static final String PADDING = "PKCS5Padding";
    private static final int IV_LENGTH = 16;

    private SecretKeySpec secretKey;
    private IvParameterSpec ivParameterSpec;

    public AESIVReuseOFB3(byte[] key) {
        secretKey = new SecretKeySpec(key, ALGORITHM);
        IvParameterSpec ivParameterSpec = generateIV();
    }

    public byte[] encrypt(String message, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(message.getBytes());
        return encrypted;
    }

    public String decrypt(byte[] encrypted, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted);
    }

    private IvParameterSpec generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static void main(String[] args) {
        try {
            // Generate a key
            byte[] key = new byte[16];
            new SecureRandom().nextBytes(key);

            // Create instances for three different parties
            AESIVReuseOFB3 party1 = new AESIVReuseOFB3(key);
            AESIVReuseOFB3 party2 = new AESIVReuseOFB3(key);
            AESIVReuseOFB3 party3 = new AESIVReuseOFB3(key);

            // Messages to be sent
            String message1 = "Hello, party 2!";
            String message2 = "Greetings, party 3!";
            String message3 = "Nice to meet you, party 1!";

            // Encrypt and send messages between parties
            byte[] iv1 = party1.ivParameterSpec.getIV();
            byte[] encryptedMessage1 = party1.encrypt(message1, iv1);
            byte[] decryptedMessage1 = party2.decrypt(encryptedMessage1, iv1).getBytes();
            System.out.println("Party 1 sent the message: " + message1);
            System.out.println("Party 2 received and decrypted the message: " + decryptedMessage1);

            byte[] iv2 = party2.ivParameterSpec.getIV();
            byte[] encryptedMessage2 = party2.encrypt(message2, iv2);
            byte[] decryptedMessage2 = party3.decrypt(encryptedMessage2, iv2).getBytes();
            System.out.println("Party 2 sent the message: " + message2);
            System.out.println("Party 3 received and decrypted the message: " + decryptedMessage2);

            byte[] iv3 = party3.ivParameterSpec.getIV();
            byte[] encryptedMessage3 = party3.encrypt(message3, iv3);
            byte[] decryptedMessage3 = party1.decrypt(encryptedMessage3, iv3).getBytes();
            System.out.println("Party 3 sent the message: " + message3);
            System.out.println("Party 1 received and decrypted the message: " + decryptedMessage3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}