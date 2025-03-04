import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SymmetricEncryptionCFB3 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CFB/NoPadding";
    private static final int IV_LENGTH = 16;

    private byte[] key;

    public SymmetricEncryptionCFB3(byte[] key) {
        this.key = key;
    }

    public String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        byte[] iv = generateIV();
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedText = cipher.doFinal(plaintext.getBytes());
        
        byte[] ivAndEncryptedText = new byte[IV_LENGTH + encryptedText.length];
        System.arraycopy(iv, 0, ivAndEncryptedText, 0, IV_LENGTH);
        System.arraycopy(encryptedText, 0, ivAndEncryptedText, IV_LENGTH, encryptedText.length);

        return Base64.getEncoder().encodeToString(ivAndEncryptedText);
    }

    public String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] iv = new byte[IV_LENGTH];
        byte[] cipherText = new byte[encryptedBytes.length - IV_LENGTH];
        
        System.arraycopy(encryptedBytes, 0, iv, 0, IV_LENGTH);
        System.arraycopy(encryptedBytes, IV_LENGTH, cipherText, 0, encryptedBytes.length - IV_LENGTH);

        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] decryptedText = cipher.doFinal(cipherText);

        return new String(decryptedText);
    }

    private byte[] generateIV() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }
}