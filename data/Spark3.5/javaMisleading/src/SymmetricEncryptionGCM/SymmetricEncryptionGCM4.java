import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionGCM4 {
    private SecretKey secretKey;

    public SymmetricEncryptionGCM4(byte[] key) {
        this.secretKey = new SecretKeySpec(key, "AES");
    }

    public String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] encryptedText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        byte[] cipherTextWithIv = new byte[iv.length + encryptedText.length];
        System.arraycopy(iv, 0, cipherTextWithIv, 0, iv.length);
        System.arraycopy(encryptedText, 0, cipherTextWithIv, iv.length, encryptedText.length);
        return Base64.getEncoder().encodeToString(cipherTextWithIv);
    }

    public String decrypt(String cipherText) throws Exception {
        byte[] cipherTextWithIv = Base64.getDecoder().decode(cipherText);
        byte[] iv = new byte[12];
        System.arraycopy(cipherTextWithIv, 0, iv, 0, iv.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] decryptedText = cipher.doFinal(cipherTextWithIv, iv.length, cipherTextWithIv.length - iv.length);
        return new String(decryptedText, StandardCharsets.UTF_8);
    }
}