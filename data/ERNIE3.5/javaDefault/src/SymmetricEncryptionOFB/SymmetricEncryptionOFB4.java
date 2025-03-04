import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionOFB4 {

    private static final String ALGORITHM = "AES/OFB/NoPadding";
    private static final int KEY_SIZE = 128; // You can also use 192 or 256
    private byte[] key;
    private byte[] iv;

    public SymmetricEncryptionOFB4() {
        SecureRandom random = new SecureRandom();
        this.key = new byte[KEY_SIZE / 8];
        this.iv = new byte[16]; // AES requires 16 byte IV for OFB mode
        random.nextBytes(this.key);
        random.nextBytes(this.iv);
    }

    public String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public String decrypt(String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    // Getters for key and iv if needed for serialization or testing
    public byte[] getKey() {
        return key;
    }

    public byte[] getIv() {
        return iv;
    }

    public static void main(String[] args) {
        try {
            SymmetricEncryptionOFB4 encryptor = new SymmetricEncryptionOFB4();
            String originalData = "Hello, World!";
            String encryptedData = encryptor.encrypt(originalData);
            String decryptedData = encryptor.decrypt(encryptedData);

            System.out.println("Original Data: " + originalData);
            System.out.println("Encrypted Data: " + encryptedData);
            System.out.println("Decrypted Data: " + decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}