import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SymmetricEncryptionGCM3 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128; // 16 bytes
    private static final int KEY_LENGTH = 256; // 32 bytes

    private byte[] key;
    private byte[] nonce;

    public SymmetricEncryptionGCM3(byte[] key, byte[] nonce) {
        this.key = key;
        this.nonce = nonce;
    }

    public String encrypt(String plainText) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, nonce);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Combine nonce, cipher text and tag
        byte[] result = new byte[nonce.length + cipherText.length];
        System.arraycopy(nonce, 0, result, 0, nonce.length);
        System.arraycopy(cipherText, 0, result, nonce.length, cipherText.length);

        return Base64.getEncoder().encodeToString(result);
    }

    public String decrypt(String cipherText) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] data = Base64.getDecoder().decode(cipherText);
        byte[] nonce = new byte[data.length - 1];
        byte[] cipherBytes = new byte[data.length - nonce.length];

        System.arraycopy(data, 0, nonce, 0, nonce.length);
        System.arraycopy(data, nonce.length, cipherBytes, 0, cipherBytes.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, nonce);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
        byte[] plainText = cipher.doFinal(cipherBytes);

        return new String(plainText, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            // Generate a random key and nonce
            byte[] key = new byte[KEY_LENGTH / 8];
            byte[] nonce = new byte[12];
            java.security.SecureRandom secureRandom = new java.security.SecureRandom();
            secureRandom.nextBytes(key);
            secureRandom.nextBytes(nonce);

            SymmetricEncryptionGCM3 symmetricEncryptionGCM3 = new SymmetricEncryptionGCM3(key, nonce);

            // Test encryption
            String originalText = "Hello, World!";
            String encryptedText = symmetricEncryptionGCM3.encrypt(originalText);
            System.out.println("Encrypted Text: " + encryptedText);

            // Test decryption
            String decryptedText = symmetricEncryptionGCM3.decrypt(encryptedText);
            System.out.println("Decrypted Text: " + decryptedText);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}