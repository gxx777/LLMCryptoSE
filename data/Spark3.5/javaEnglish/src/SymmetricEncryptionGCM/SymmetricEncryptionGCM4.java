import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionGCM4 {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128; // in bits
    private static final int IV_LENGTH = 12; // in bytes

    public String encrypt(String plainText, SecretKey secretKey) throws Exception {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        byte[] encryptedText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        byte[] cipherTextWithIv = new byte[iv.length + encryptedText.length];
        System.arraycopy(iv, 0, cipherTextWithIv, 0, iv.length);
        System.arraycopy(encryptedText, 0, cipherTextWithIv, iv.length, encryptedText.length);

        return Base64.getEncoder().encodeToString(cipherTextWithIv);
    }

    public String decrypt(String cipherText, SecretKey secretKey) throws Exception {
        byte[] cipherTextWithIv = Base64.getDecoder().decode(cipherText);

        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(cipherTextWithIv, 0, iv, 0, iv.length);

        byte[] encryptedText = new byte[cipherTextWithIv.length - iv.length];
        System.arraycopy(cipherTextWithIv, iv.length, encryptedText, 0, encryptedText.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

        byte[] decryptedText = cipher.doFinal(encryptedText);

        return new String(decryptedText, StandardCharsets.UTF_8);
    }
}