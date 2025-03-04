import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionOFB2 {

    private static final String ALGORITHM = "AES/OFB/NoPadding";
    private static final int KEY_SIZE = 128;
    private static final int INIT_VECTOR_SIZE = 16; // AES requires 16 bytes initialization vector

    private byte[] key;
    private byte[] initVector;

    public SymmetricEncryptionOFB2() {
        SecureRandom random = new SecureRandom();
        key = new byte[KEY_SIZE / 8];
        initVector = new byte[INIT_VECTOR_SIZE / 8];
        random.nextBytes(key);
        random.nextBytes(initVector);
    }

    public String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(initVector);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public String decrypt(String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(initVector);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));

        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            SymmetricEncryptionOFB2 encryptor = new SymmetricEncryptionOFB2();

            String originalText = "Hello, World!";
            String encryptedText = encryptor.encrypt(originalText);
            String decryptedText = encryptor.decrypt(encryptedText);

            System.out.println("Original Text: " + originalText);
            System.out.println("Encrypted Text: " + encryptedText);
            System.out.println("Decrypted Text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}