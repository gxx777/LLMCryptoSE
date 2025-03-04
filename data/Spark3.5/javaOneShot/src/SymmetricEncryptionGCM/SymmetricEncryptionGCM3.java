import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionGCM3 {
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    public static String encrypt(String plainText, SecretKey secretKey) throws Exception {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

        byte[] encryptedText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        byte[] cipherTextWithIv = new byte[iv.length + encryptedText.length];

        System.arraycopy(iv, 0, cipherTextWithIv, 0, iv.length);
        System.arraycopy(encryptedText, 0, cipherTextWithIv, iv.length, encryptedText.length);

        return Base64.getEncoder().encodeToString(cipherTextWithIv);
    }

    public static String decrypt(String cipherText, SecretKey secretKey) throws Exception {
        byte[] cipherTextWithIv = Base64.getDecoder().decode(cipherText);
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(cipherTextWithIv, 0, iv, 0, iv.length);

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

        byte[] decryptedText = cipher.doFinal(cipherTextWithIv, iv.length, cipherTextWithIv.length - iv.length);

        return new String(decryptedText, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        String key = "abcdefghijklmnop"; // 请确保密钥长度为16个字符
        SecretKey secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

        String plainText = "Hello, World!";
        String encryptedText = encrypt(plainText, secretKey);
        System.out.println("Encrypted text: " + encryptedText);

        String decryptedText = decrypt(encryptedText, secretKey);
        System.out.println("Decrypted text: " + decryptedText);
    }
}