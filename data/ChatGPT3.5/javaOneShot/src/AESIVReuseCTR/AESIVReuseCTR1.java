import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class AESIVReuseCTR1 {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "CTR";
    private static final String PADDING = "NoPadding";

    private static byte[] generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private static byte[] encrypt(String key, byte[] iv, String message) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(message.getBytes());
    }

    private static String decrypt(String key, byte[] iv, byte[] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return new String(cipher.doFinal(encrypted));
    }

    public static void main(String[] args) {
        try {
            // Generate random IV for each participant
            byte[] iv1 = generateIV();
            byte[] iv2 = generateIV();
            byte[] iv3 = generateIV();
            
            // Generate random key for encryption
            String key = "thisIsASecretKey";

            // Sender 1 encrypts and sends a message
            String message1 = "Hello from Sender 1";
            byte[] encrypted1 = encrypt(key, iv1, Arrays.toString(message1.getBytes()));
            System.out.println("Sender 1 sends: " + Base64.getEncoder().encodeToString(encrypted1));

            // Sender 2 encrypts and sends a message
            String message2 = "Hello from Sender 2";
            byte[] encrypted2 = encrypt(key, iv2, Arrays.toString(message2.getBytes()));
            System.out.println("Sender 2 sends: " + Base64.getEncoder().encodeToString(encrypted2));

            // Sender 3 encrypts and sends a message
            String message3 = "Hello from Sender 3";
            byte[] encrypted3 = encrypt(key, iv3, Arrays.toString(message3.getBytes()));
            System.out.println("Sender 3 sends: " + Base64.getEncoder().encodeToString(encrypted3));

            // Receivers decrypt the message
            String decrypted1 = decrypt(key, iv1, encrypted1);
            String decrypted2 = decrypt(key, iv2, encrypted2);
            String decrypted3 = decrypt(key, iv3, encrypted3);

            System.out.println("Receiver 1 receives: " + decrypted1);
            System.out.println("Receiver 2 receives: " + decrypted2);
            System.out.println("Receiver 3 receives: " + decrypted3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}