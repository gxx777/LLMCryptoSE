import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class AESIVReuseOFB1 {

    private static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private static IvParameterSpec generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static byte[] encrypt(String message, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(message.getBytes());
    }

    public static String decrypt(byte[] cipherText, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decryptedBytes = cipher.doFinal(cipherText);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        SecretKey keyA = generateKey();
        IvParameterSpec ivA = generateIV();
        SecretKey keyB = generateKey();
        IvParameterSpec ivB = generateIV();
        SecretKey keyC = generateKey();
        IvParameterSpec ivC = generateIV();

        String messageToA = "Message for participant A";
        String messageToB = "Message for participant B";
        String messageToC = "Message for participant C";

        byte[] encryptedMessageToA = encrypt(messageToA, keyA, ivA);
        byte[] encryptedMessageToB = encrypt(messageToB, keyB, ivB);
        byte[] encryptedMessageToC = encrypt(messageToC, keyC, ivC);

        String decryptedMessageToA = decrypt(encryptedMessageToA, keyA, ivA);
        String decryptedMessageToB = decrypt(encryptedMessageToB, keyB, ivB);
        String decryptedMessageToC = decrypt(encryptedMessageToC, keyC, ivC);

        System.out.println("Decrypted message for participant A: " + decryptedMessageToA);
        System.out.println("Decrypted message for participant B: " + decryptedMessageToB);
        System.out.println("Decrypted message for participant C: " + decryptedMessageToC);
    }
}