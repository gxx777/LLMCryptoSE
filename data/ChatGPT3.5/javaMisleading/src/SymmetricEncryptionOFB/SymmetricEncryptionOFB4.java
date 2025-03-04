import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SymmetricEncryptionOFB4 {
    private static final String ALGORITHM = "AES";
    private static final String MODE = "AES/OFB/NoPadding";

    private SecretKeySpec secretKey;
    private IvParameterSpec ivParameterSpec;

    public SymmetricEncryptionOFB4(String key, String iv) {
        this.secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
        this.ivParameterSpec = new IvParameterSpec(iv.getBytes());
    }

    public String encrypt(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(MODE);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String decrypt(String ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(MODE);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        String key = "0123456789abcdef";
        String iv = "abcdef0123456789";
        String plaintext = "Hello, world!";
        
        SymmetricEncryptionOFB4 encryption = new SymmetricEncryptionOFB4(key, iv);
        String ciphertext = encryption.encrypt(plaintext);
        System.out.println("Encrypted text: " + ciphertext);
        
        String decryptedText = encryption.decrypt(ciphertext);
        System.out.println("Decrypted text: " + decryptedText);
    }
}