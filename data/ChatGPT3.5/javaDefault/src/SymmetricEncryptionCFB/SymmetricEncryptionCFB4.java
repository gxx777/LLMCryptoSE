import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SymmetricEncryptionCFB4 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CFB/NoPadding";
    private static final String ENCODING = "UTF-8";

    private SecretKeySpec secretKey;
    private IvParameterSpec ivParameterSpec;

    public SymmetricEncryptionCFB4(String key) {
        this.secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
        this.ivParameterSpec = new IvParameterSpec(key.substring(0, 16).getBytes());
    }

    public String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(ENCODING));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes, ENCODING);
    }

    public static void main(String[] args) {
        try {
            String key = "abcdefghijklmnop"; // 16-byte key
            String plaintext = "Hello, World!";
            SymmetricEncryptionCFB4 symmetricEncryption = new SymmetricEncryptionCFB4(key);

            String encryptedText = symmetricEncryption.encrypt(plaintext);
            System.out.println("Encrypted text: " + encryptedText);

            String decryptedText = symmetricEncryption.decrypt(encryptedText);
            System.out.println("Decrypted text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}