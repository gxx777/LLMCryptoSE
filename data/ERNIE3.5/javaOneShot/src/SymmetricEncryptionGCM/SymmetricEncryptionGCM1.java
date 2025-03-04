import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SymmetricEncryptionGCM1 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128; // 16 bytes
    private static final int KEY_LENGTH = 256; // 32 bytes

    private byte[] key;
    private GCMParameterSpec gcmParameterSpec;

    public SymmetricEncryptionGCM1(byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
        if (key.length != KEY_LENGTH / 8) {
            throw new IllegalArgumentException("Invalid key length for AES-256");
        }

        this.key = key;
        this.gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, key);
    }

    public String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), gcmParameterSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public String decrypt(String ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), gcmParameterSpec);

        byte[] bytes = Base64.getDecoder().decode(ciphertext);
        byte[] plaintext = cipher.doFinal(bytes);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            byte[] key = new byte[SymmetricEncryptionGCM1.KEY_LENGTH / 8]; // 256-bit key
            // Here you should generate a secure random key
            // For demonstration purposes, we are just using zeros
            java.util.Arrays.fill(key, (byte) 0);

            SymmetricEncryptionGCM1 encryptor = new SymmetricEncryptionGCM1(key);

            String plaintext = "This is a secret message";
            String ciphertext = encryptor.encrypt(plaintext);
            System.out.println("Encrypted: " + ciphertext);

            String decryptedtext = encryptor.decrypt(ciphertext);
            System.out.println("Decrypted: " + decryptedtext);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}