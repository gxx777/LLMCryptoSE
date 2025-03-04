import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionCFB1 {

    private static final String ALGORITHM = "AES/CFB/NoPadding";
    private static final int KEY_SIZE = 128;
    private static final byte[] IV = new byte[16];

    static {
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV);
    }

    private SecretKeySpec keySpec;
    private IvParameterSpec ivSpec;

    public SymmetricEncryptionCFB1() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[KEY_SIZE / 8];
        random.nextBytes(keyBytes);
        keySpec = new SecretKeySpec(keyBytes, "AES");
        ivSpec = new IvParameterSpec(IV);
    }

    public String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public String decrypt(String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
        return new String(cipher.doFinal(decodedData), StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            SymmetricEncryptionCFB1 encryptor = new SymmetricEncryptionCFB1();

            String originalData = "Hello, World!";
            System.out.println("Original Data: " + originalData);

            String encryptedData = encryptor.encrypt(originalData);
            System.out.println("Encrypted Data: " + encryptedData);

            String decryptedData = encryptor.decrypt(encryptedData);
            System.out.println("Decrypted Data: " + decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}