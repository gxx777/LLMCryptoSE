import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionGCM1 {

    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_NONCE_LENGTH = 12;

    public static String encrypt(String plaintext, String key) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(key);
        Key secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(nonce);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        byte[] result = new byte[nonce.length + encryptedBytes.length];
        System.arraycopy(nonce, 0, result, 0, nonce.length);
        System.arraycopy(encryptedBytes, 0, result, nonce.length, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(result);
    }

    public static String decrypt(String ciphertext, String key) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(key);
        Key secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        byte[] decodedBytes = Base64.getDecoder().decode(ciphertext);
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        byte[] encryptedBytes = new byte[decodedBytes.length - GCM_NONCE_LENGTH];
        System.arraycopy(decodedBytes, 0, nonce, 0, GCM_NONCE_LENGTH);
        System.arraycopy(decodedBytes, GCM_NONCE_LENGTH, encryptedBytes, 0, encryptedBytes.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        String plaintext = "Hello, World!";
        String key = "examplekeyexample";

        String encryptedText = encrypt(plaintext, key);
        System.out.println("Encrypted text: " + encryptedText);

        String decryptedText = decrypt(encryptedText, key);
        System.out.println("Decrypted text: " + decryptedText);
    }
}