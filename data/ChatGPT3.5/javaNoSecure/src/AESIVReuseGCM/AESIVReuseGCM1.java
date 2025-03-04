import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.security.Key;
import java.security.SecureRandom;

public class AESIVReuseGCM1 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    public static void main(String[] args) throws Exception {
        // Generate random key
        Key key = generateKey();
        
        // Sender 1 encrypts message and sends to Receiver 1
        String message1 = "Message from Sender 1";
        byte[] encryptedMessage1 = encrypt(message1, key);
        System.out.println("Sender 1 sends encrypted message to Receiver 1: " + new String(encryptedMessage1));
        
        // Receiver 1 decrypts message from Sender 1
        String decryptedMessage1 = decrypt(encryptedMessage1, key);
        System.out.println("Receiver 1 decrypts message from Sender 1: " + decryptedMessage1);
        
        // Sender 2 encrypts message and sends to Receiver 2
        String message2 = "Message from Sender 2";
        byte[] encryptedMessage2 = encrypt(message2, key);
        System.out.println("Sender 2 sends encrypted message to Receiver 2: " + new String(encryptedMessage2));
        
        // Receiver 2 decrypts message from Sender 2
        String decryptedMessage2 = decrypt(encryptedMessage2, key);
        System.out.println("Receiver 2 decrypts message from Sender 2: " + decryptedMessage2);
    }

    private static Key generateKey() throws Exception {
        byte[] key = new byte[16]; // 128 bit key
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(key);
        return new javax.crypto.spec.SecretKeySpec(key, "AES");
    }

    private static byte[] encrypt(String message, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] encrypted = cipher.doFinal(message.getBytes());
        return encrypted;
    }

    private static String decrypt(byte[] encrypted, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(encrypted, 0, iv, 0, IV_LENGTH);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decrypted = cipher.doFinal(encrypted, IV_LENGTH, encrypted.length - IV_LENGTH);
        return new String(decrypted);
    }
}