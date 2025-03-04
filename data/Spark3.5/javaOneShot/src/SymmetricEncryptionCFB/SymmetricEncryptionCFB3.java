import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionCFB3 {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CFB8/NoPadding";
    private static final int IV_SIZE = 16;
    private static final int KEY_SIZE = 16;

    public static String encrypt(String plainText, SecretKey secretKey) throws Exception {
        byte[] iv = generateRandomIV();
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    public static String decrypt(String encryptedText, SecretKey secretKey) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(encryptedText);

        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(decoded, 0, iv, 0, iv.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        byte[] encrypted = new byte[decoded.length - iv.length];
        System.arraycopy(decoded, iv.length, encrypted, 0, encrypted.length);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        byte[] decrypted = cipher.doFinal(encrypted);

        return new String(decrypted, StandardCharsets.UTF_8);
    }

    private static byte[] generateRandomIV() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static void main(String[] args) throws Exception {
        String key = "abcdefghijklmnop"; // 请确保密钥长度为16字节
        SecretKey secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM);

        String plainText = "Hello, World!";
        String encryptedText = encrypt(plainText, secretKey);
        String decryptedText = decrypt(encryptedText, secretKey);

        System.out.println("原文： " + plainText);
        System.out.println("加密后： " + encryptedText);
        System.out.println("解密后： " + decryptedText);
    }
}