import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SymmetricEncryptionCTR3 {
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String CIPHER_MODE = "AES/CTR/NoPadding";
    private static final int IV_SIZE = 16;

    private SecretKeySpec secretKey;

    public SymmetricEncryptionCTR3(byte[] key) {
        this.secretKey = new SecretKeySpec(key, ENCRYPTION_ALGORITHM);
    }

    public String encrypt(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_MODE);
            byte[] iv = new byte[IV_SIZE];
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public String decrypt(String ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_MODE);
            byte[] iv = new byte[IV_SIZE];
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        String key = "ThisIsASecretKey";
        SymmetricEncryptionCTR3 symmetricEncryption = new SymmetricEncryptionCTR3(key.getBytes());

        String plaintext = "Hello, World!";
        String ciphertext = symmetricEncryption.encrypt(plaintext);
        System.out.println("Encrypted text: " + ciphertext);

        String decryptedText = symmetricEncryption.decrypt(ciphertext);
        System.out.println("Decrypted text: " + decryptedText);
    }
}