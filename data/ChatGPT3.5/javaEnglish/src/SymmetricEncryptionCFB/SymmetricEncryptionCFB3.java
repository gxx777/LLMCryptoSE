import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SymmetricEncryptionCFB3 {
    
    private static final String ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CFB/NoPadding";
    private static final String IV = "0123456789abcdef";

    private SecretKeySpec secretKey;
    private IvParameterSpec ivParameterSpec;

    public SymmetricEncryptionCFB3(String key) {
        this.secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
        this.ivParameterSpec = new IvParameterSpec(IV.getBytes());
    }

    public String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            String key = "secretkey1234567";
            SymmetricEncryptionCFB3 symmetricEncryption = new SymmetricEncryptionCFB3(key);
            String plaintext = "Hello, World!";
            String encryptedText = symmetricEncryption.encrypt(plaintext);
            System.out.println("Encrypted text: " + encryptedText);
            String decryptedText = symmetricEncryption.decrypt(encryptedText);
            System.out.println("Decrypted text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}