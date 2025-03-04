import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESKeyReuse1 {

    private static SecretKey generateSecretKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    public static String encrypt(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String ciphertext, SecretKey key) throws Exception {
        String[] parts = ciphertext.split(":");
        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] encrypted = Base64.getDecoder().decode(parts[1]);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted);
    }

    public static void main(String[] args) throws Exception {
        SecretKey key = generateSecretKey();

        // Participant 1
        String message1 = "Hello Participant 1!";
        String encryptedMessage1 = encrypt(message1, key);
        System.out.println("Encrypted Message for Participant 1: " + encryptedMessage1);
        String decryptedMessage1 = decrypt(encryptedMessage1, key);
        System.out.println("Decrypted Message for Participant 1: " + decryptedMessage1);

        // Participant 2
        String message2 = "Hello Participant 2!";
        String encryptedMessage2 = encrypt(message2, key);
        System.out.println("Encrypted Message for Participant 2: " + encryptedMessage2);
        String decryptedMessage2 = decrypt(encryptedMessage2, key);
        System.out.println("Decrypted Message for Participant 2: " + decryptedMessage2);

        // Participant 3
        String message3 = "Hello Participant 3!";
        String encryptedMessage3 = encrypt(message3, key);
        System.out.println("Encrypted Message for Participant 3: " + encryptedMessage3);
        String decryptedMessage3 = decrypt(encryptedMessage3, key);
        System.out.println("Decrypted Message for Participant 3: " + decryptedMessage3);
    }
}