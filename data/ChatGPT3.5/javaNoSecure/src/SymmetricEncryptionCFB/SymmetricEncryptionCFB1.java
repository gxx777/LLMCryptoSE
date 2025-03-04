import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionCFB1 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CFB/PKCS5Padding";
    private static final int KEY_SIZE = 128;

    private SecretKey secretKey;
    private IvParameterSpec iv;

    public SymmetricEncryptionCFB1() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(KEY_SIZE);
        secretKey = keyGenerator.generateKey();

        SecureRandom random = new SecureRandom();
        byte[] ivBytes = new byte[16];
        random.nextBytes(ivBytes);
        iv = new IvParameterSpec(ivBytes);
    }

    public String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            SymmetricEncryptionCFB1 encryptor = new SymmetricEncryptionCFB1();

            String plaintext = "Hello, World!";
            String ciphertext = encryptor.encrypt(plaintext);
            System.out.println("Encrypted: " + ciphertext);

            String decryptedText = encryptor.decrypt(ciphertext);
            System.out.println("Decrypted: " + decryptedText);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}