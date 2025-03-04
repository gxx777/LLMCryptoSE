import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionGCM3 {

    private static final int TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;
    private static final int KEY_LENGTH = 16;

    private SecretKeySpec secretKey;

    public SymmetricEncryptionGCM3(byte[] key) {
        this.secretKey = new SecretKeySpec(key, "AES");
    }

    public String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = generateIV();

        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        byte[] cipherText = cipher.doFinal(plaintext.getBytes());

        byte[] cipherTextWithIV = new byte[IV_LENGTH + cipherText.length];
        System.arraycopy(iv, 0, cipherTextWithIV, 0, IV_LENGTH);
        System.arraycopy(cipherText, 0, cipherTextWithIV, IV_LENGTH, cipherText.length);

        return Base64.getEncoder().encodeToString(cipherTextWithIV);
    }

    public String decrypt(String cipherText) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] cipherTextBytes = Base64.getDecoder().decode(cipherText);
        byte[] iv = new byte[IV_LENGTH];
        byte[] text = new byte[cipherTextBytes.length - IV_LENGTH];
        System.arraycopy(cipherTextBytes, 0, iv, 0, IV_LENGTH);
        System.arraycopy(cipherTextBytes, IV_LENGTH, text, 0, text.length);

        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

        byte[] plainText = cipher.doFinal(text);

        return new String(plainText);
    }

    private byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}