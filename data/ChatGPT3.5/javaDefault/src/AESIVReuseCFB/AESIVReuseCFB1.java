import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.SecureRandom;

public class AESIVReuseCFB1 {

    public static void main(String[] args) throws Exception {
        // Generate a AES key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();

        // Create an AES cipher for CFB mode
        Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");

        // Generate an initialization vector (IV) for the first participant
        byte[] iv1 = generateIV();
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new javax.crypto.spec.IvParameterSpec(iv1));

        // Encrypt message for participant 1
        byte[] encryptedMessage1 = cipher.doFinal("Message for participant 1".getBytes());
        System.out.println("Encrypted message for participant 1: " + new String(encryptedMessage1));

        // Generate an initialization vector (IV) for the second participant
        byte[] iv2 = generateIV();
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new javax.crypto.spec.IvParameterSpec(iv2));

        // Encrypt message for participant 2
        byte[] encryptedMessage2 = cipher.doFinal("Message for participant 2".getBytes());
        System.out.println("Encrypted message for participant 2: " + new String(encryptedMessage2));

        // Generate an initialization vector (IV) for the third participant
        byte[] iv3 = generateIV();
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new javax.crypto.spec.IvParameterSpec(iv3));

        // Encrypt message for participant 3
        byte[] encryptedMessage3 = cipher.doFinal("Message for participant 3".getBytes());
        System.out.println("Encrypted message for participant 3: " + new String(encryptedMessage3));
    }

    private static byte[] generateIV() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16]; // IV size for AES is 16 bytes
        secureRandom.nextBytes(iv);
        return iv;
    }
}