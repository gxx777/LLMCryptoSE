import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionCFB3 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CFB/NoPadding";
    private static final int IV_LENGTH = 16;

    private SecretKeySpec secretKey;
    private byte[] iv;

    public SymmetricEncryptionCFB3(byte[] key) {
        this.secretKey = new SecretKeySpec(key, ALGORITHM);
        this.iv = generateIV();
    }

    private byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public String encrypt(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            System.out.println("Encryption Error: " + e.getMessage());
            return null;
        }
    }

    public String decrypt(String ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
            return new String(decryptedBytes);
        } catch (Exception e) {
            System.out.println("Decryption Error: " + e.getMessage());
            return null;
        }
    }

    public static void main(String[] args) {
        String key = "your_secret_key_here";
        SymmetricEncryptionCFB3 encryptor = new SymmetricEncryptionCFB3(key.getBytes());

        String plaintext = "Hello, this is a test message!";
        String encryptedText = encryptor.encrypt(plaintext);

        System.out.println("Encrypted Text: " + encryptedText);
        System.out.println("Decrypted Text: " + encryptor.decrypt(encryptedText));
    }
}