import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SymmetricEncryptionCTR4 {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "AES/CTR/NoPadding";
    private static final int IV_LENGTH = 16;

    private SecretKeySpec secretKey;
    private IvParameterSpec ivParameterSpec;

    public SymmetricEncryptionCTR4(byte[] key) {
        this.secretKey = new SecretKeySpec(key, ALGORITHM);
        this.ivParameterSpec = generateIv();
    }

    private IvParameterSpec generateIv() {
        byte[] iv = new byte[IV_LENGTH];
        // Generate a random IV
        // You can use a more secure method for generating IVs
        return new IvParameterSpec(iv);
    }

    public String encrypt(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(MODE);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String decrypt(String ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(MODE);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        byte[] key = "abcdefghijklmnop".getBytes(StandardCharsets.UTF_8);
        SymmetricEncryptionCTR4 encryptor = new SymmetricEncryptionCTR4(key);

        String plaintext = "Hello, world!";
        String ciphertext = encryptor.encrypt(plaintext);
        System.out.println("Ciphertext: " + ciphertext);

        String decryptedText = encryptor.decrypt(ciphertext);
        System.out.println("Decrypted text: " + decryptedText);
    }
}