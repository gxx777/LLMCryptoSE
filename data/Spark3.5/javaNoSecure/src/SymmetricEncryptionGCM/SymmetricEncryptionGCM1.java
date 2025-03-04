import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionGCM1 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    public static void main(String[] args) throws Exception {
        String plainText = "Hello, World!";
        SecretKey secretKey = generateSecretKey();

        String encryptedText = encrypt(plainText, secretKey);
        System.out.println("Encrypted text: " + encryptedText);

        String decryptedText = decrypt(encryptedText, secretKey);
        System.out.println("Decrypted text: " + decryptedText);
    }

    private static SecretKey generateSecretKey() {
        byte[] keyBytes = new byte[16];
        new SecureRandom().nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static String encrypt(String plainText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        byte[] cipherTextWithIv = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, cipherTextWithIv, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, cipherTextWithIv, iv.length, encryptedBytes.length);
        return Base64.getEncoder().encodeToString(cipherTextWithIv);
    }

    private static String decrypt(String encryptedText, SecretKey secretKey) throws Exception {
        byte[] cipherTextWithIv = Base64.getDecoder().decode(encryptedText);
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(cipherTextWithIv, 0, iv, 0, iv.length);
        byte[] encryptedBytes = new byte[cipherTextWithIv.length - iv.length];
        System.arraycopy(cipherTextWithIv, iv.length, encryptedBytes, 0, encryptedBytes.length);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}