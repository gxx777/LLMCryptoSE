import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SymmetricEncryptionGCM2 {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128;
    private static final int KEY_LENGTH = 256;

    private SecretKey key;
    private GCMParameterSpec gcmSpec;

    public SymmetricEncryptionGCM2() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_LENGTH);
        this.key = keyGenerator.generateKey();
        this.gcmSpec = new GCMParameterSpec(TAG_LENGTH, new byte[0]);
    }

    public String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public String decrypt(String ciphertext) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(ciphertext);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        byte[] plaintext = cipher.doFinal(bytes);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            SymmetricEncryptionGCM2 encryptor = new SymmetricEncryptionGCM2();
            String plaintext = "Hello, World!";
            String ciphertext = encryptor.encrypt(plaintext);
            System.out.println("Encrypted: " + ciphertext);
            String decryptedtext = encryptor.decrypt(ciphertext);
            System.out.println("Decrypted: " + decryptedtext);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}