import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SymmetricEncryptionCFB4 {
    private static final String ALGORITHM = "AES";
    private static final String MODE = "AES/CFB/NoPadding";
    private static final int IV_LENGTH = 16;
    private static final String CHARSET = "UTF-8";

    private SecretKeySpec secretKey;
    private IvParameterSpec ivParameterSpec;

    public SymmetricEncryptionCFB4(byte[] key) {
        secretKey = new SecretKeySpec(key, ALGORITHM);
        ivParameterSpec = new IvParameterSpec(key, 0, IV_LENGTH);
    }

    public String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(MODE);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(CHARSET));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(MODE);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes, CHARSET);
    }

    public static void main(String[] args) throws Exception {
        byte[] key = "secretkey1234567".getBytes(CHARSET);
        SymmetricEncryptionCFB4 crypto = new SymmetricEncryptionCFB4(key);

        String plaintext = "Hello, world!";
        String ciphertext = crypto.encrypt(plaintext);
        System.out.println("Encrypted text: " + ciphertext);

        String decryptedText = crypto.decrypt(ciphertext);
        System.out.println("Decrypted text: " + decryptedText);
    }
}