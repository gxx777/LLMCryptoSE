import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseOFB4 {
    private static final String ALGORITHM = "AES/OFB/NoPadding";
    private static final int KEY_SIZE = 128; // AES key size in bits

    private Key key;
    private byte[] iv;

    public AESIVReuseOFB4(byte[] keyBytes) throws Exception {
        this.key = new SecretKeySpec(keyBytes, "AES");
        this.iv = new byte[16]; // AES block size is 16 bytes
        new SecureRandom().nextBytes(iv); // Generate a random IV
    }

    public String encrypt(String plainText, byte[] keyBytes) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), ivSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decrypt(String cipherText, byte[] keyBytes) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), ivSpec);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(decrypted);
    }

    public static void main(String[] args) throws Exception {
        // Example usage
        AESIVReuseOFB4 aes = new AESIVReuseOFB4(new byte[16]); // Key initialization should be done securely
        String message = "Hello, World!";

        // Encrypt message with key1
        String encrypted1 = aes.encrypt(message, new byte[16]);
        System.out.println("Encrypted message 1: " + encrypted1);

        // Decrypt message with key1
        String decrypted1 = aes.decrypt(encrypted1, new byte[16]);
        System.out.println("Decrypted message 1: " + decrypted1);

        // Encrypt message with key2 (should be different from key1)
        String encrypted2 = aes.encrypt(message, new byte[16]);
        System.out.println("Encrypted message 2: " + encrypted2);

        // Decrypt message with key2
        String decrypted2 = aes.decrypt(encrypted2, new byte[16]);
        System.out.println("Decrypted message 2: " + decrypted2);
    }
}