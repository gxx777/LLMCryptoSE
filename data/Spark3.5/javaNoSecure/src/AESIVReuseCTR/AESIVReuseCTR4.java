import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR4 {
    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final int IV_SIZE = 16;

    public static String encrypt(String key, String value) throws Exception {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encrypted = cipher.doFinal(value.getBytes());

        byte[] cipherWithIv = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, cipherWithIv, 0, iv.length);
        System.arraycopy(encrypted, 0, cipherWithIv, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(cipherWithIv);
    }

    public static String decrypt(String key, String encrypted) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(encrypted);
        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(bytes, 0, iv, 0, iv.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        int encryptedSize = bytes.length - IV_SIZE;
        byte[] encryptedBytes = new byte[encryptedSize];
        System.arraycopy(bytes, IV_SIZE, encryptedBytes, 0, encryptedSize);

        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] decrypted = cipher.doFinal(encryptedBytes);

        return new String(decrypted);
    }
}