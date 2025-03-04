import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SymmetricEncryptionCTR4 {
    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final String KEY = "abcdefghijklmnop"; // 16 chars = 128 bit key

    public static String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKey = new SecretKeySpec(KEY.getBytes(), "AES");
        IvParameterSpec ivparameterspec = new IvParameterSpec(KEY.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivparameterspec);
        byte[] encryptedText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedText);
    }

    public static String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKey = new SecretKeySpec(KEY.getBytes(), "AES");
        IvParameterSpec ivparameterspec = new IvParameterSpec(KEY.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivparameterspec);
        byte[] decryptedText = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedText);
    }
}