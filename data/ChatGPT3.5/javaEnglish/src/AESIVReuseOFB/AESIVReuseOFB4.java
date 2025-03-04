import java.security.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;

public class AESIVReuseOFB4 {

    private static SecretKey secretKey;
    private static IvParameterSpec ivParameterSpec;

    public AESIVReuseOFB4() {
        try {
            secretKey = generateKey();
            ivParameterSpec = generateIV();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private IvParameterSpec generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public byte[] encryptMessage(String message, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(message.getBytes());
    }

    public String decryptMessage(byte[] encryptedMessage, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decryptedMessage = cipher.doFinal(encryptedMessage);
        return new String(decryptedMessage);
    }

    public static void main(String[] args) {
        AESIVReuseOFB4 aesIvReuseOFB4 = new AESIVReuseOFB4();

        try {
            String message1 = Arrays.toString(aesIvReuseOFB4.encryptMessage("Hello participant 1!", secretKey, ivParameterSpec));
            String message2 = Arrays.toString(aesIvReuseOFB4.encryptMessage("Hello participant 2!", secretKey, ivParameterSpec));
            String message3 = Arrays.toString(aesIvReuseOFB4.encryptMessage("Hello participant 3!", secretKey, ivParameterSpec));

            System.out.println("Participant 1 received: " + aesIvReuseOFB4.decryptMessage(message1.getBytes(), secretKey, ivParameterSpec));
            System.out.println("Participant 2 received: " + aesIvReuseOFB4.decryptMessage(message2.getBytes(), secretKey, ivParameterSpec));
            System.out.println("Participant 3 received: " + aesIvReuseOFB4.decryptMessage(message3.getBytes(), secretKey, ivParameterSpec));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}