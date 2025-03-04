import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionGCM1 {

    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;

    public static String encrypt(String plaintext, SecretKey key) throws Exception {
        byte[] iv = new byte[IV_LENGTH_BYTE];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
        byte[] message = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, message, 0, iv.length);
        System.arraycopy(ciphertext, 0, message, iv.length, ciphertext.length);

        return Base64.getEncoder().encodeToString(message);
    }

    public static String decrypt(String ciphertext, SecretKey key) throws Exception {
        byte[] message = Base64.getDecoder().decode(ciphertext);
        byte[] iv = new byte[IV_LENGTH_BYTE];
        System.arraycopy(message, 0, iv, 0, IV_LENGTH_BYTE);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);

        byte[] plaintext = cipher.doFinal(message, IV_LENGTH_BYTE, message.length - IV_LENGTH_BYTE);

        return new String(plaintext);
    }

    public static void main(String[] args) throws Exception {
        SecretKey key = new SecretKeySpec("1234567890123456".getBytes(), "AES");

        String plainText = "Hello, GCM encryption!";
        String ciphertext = encrypt(plainText, key);
        System.out.println("Ciphertext: " + ciphertext);

        String decryptedText = decrypt(ciphertext, key);
        System.out.println("Decrypted Text: " + decryptedText);
    }
}