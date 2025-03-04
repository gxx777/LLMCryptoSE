import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class SymmetricEncryptionGCM2 {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;

    private SecretKey secretKey;

    public SymmetricEncryptionGCM2(byte[] key) {
        this.secretKey = new SecretKeySpec(key, "AES");
    }

    public byte[] encrypt(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] iv = new byte[IV_LENGTH_BYTE];
            cipher.updateAAD(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] ciphertext = cipher.doFinal(iv);

            return ciphertext;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public String decrypt(byte[] ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            byte[] iv = new byte[IV_LENGTH_BYTE];
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
            String plaintext = new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);

            return plaintext;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static void main(String[] args) {
        try {
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(256);
            SecretKey key = keygen.generateKey();

            SymmetricEncryptionGCM2 aes = new SymmetricEncryptionGCM2(key.getEncoded());
            String plaintext = "Hello, world!";
            byte[] ciphertext = aes.encrypt(plaintext);
            System.out.println("Encrypted: " + new String(ciphertext));

            String decrypted = aes.decrypt(ciphertext);
            System.out.println("Decrypted: " + decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}