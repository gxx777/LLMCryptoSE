import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SymmetricEncryptionCBC4 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    private SecretKeySpec secretKey;
    private IvParameterSpec ivParameterSpec;

    public SymmetricEncryptionCBC4(byte[] key, byte[] iv) {
        this.secretKey = new SecretKeySpec(key, ALGORITHM);
        this.ivParameterSpec = new IvParameterSpec(iv);
    }

    public String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            byte[] key = "mykey1234567890".getBytes();
            byte[] iv = "myiv123456789012".getBytes();

            SymmetricEncryptionCBC4 encryption = new SymmetricEncryptionCBC4(key, iv);

            String plaintext = "Hello, world!";
            String ciphertext = encryption.encrypt(plaintext);
            System.out.println("Encrypted: " + ciphertext);

            String decryptedText = encryption.decrypt(ciphertext);
            System.out.println("Decrypted: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}