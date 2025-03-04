import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionGCM3 {

    private static final int TAG_LENGTH = 128; // 16 bytes
    private static final int KEY_LENGTH = 256; // 32 bytes
    private static final int INIT_VECTOR_LENGTH = 12; // 16 bytes - GCM mode

    private SecretKey key;
    private byte[] initVector;

    public SymmetricEncryptionGCM3() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_LENGTH);
        this.key = keyGenerator.generateKey();

        this.initVector = new byte[INIT_VECTOR_LENGTH];
        // Initialize the initialization vector with random values
        new SecureRandom().nextBytes(initVector);
    }

    /**
     * Encrypts the given plaintext using AES/GCM/NoPadding cipher.
     *
     * @param plaintext The plaintext to encrypt
     * @return The Base64 encoded ciphertext
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public String encrypt(String plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, initVector);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] authTag = cipher.getIV(); // GCM mode uses the IV for authentication tag

        // Combine the authentication tag with the ciphertext
        byte[] result = new byte[ciphertext.length + authTag.length];
        System.arraycopy(ciphertext, 0, result, 0, ciphertext.length);
        System.arraycopy(authTag, 0, result, ciphertext.length, authTag.length);

        return Base64.getEncoder().encodeToString(result);
    }

    /**
     * Decrypts the given ciphertext using AES/GCM/NoPadding cipher.
     *
     * @param ciphertext The Base64 encoded ciphertext to decrypt
     * @return The decrypted plaintext
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public String decrypt(String ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] encodedBytes = Base64.getDecoder().decode(ciphertext);

        // Split the authentication tag from the ciphertext
        byte[] ciphertextBytes = new byte[encodedBytes.length - INIT_VECTOR_LENGTH];
        byte[] authTag = new byte[INIT_VECTOR_LENGTH];
        System.arraycopy(encodedBytes, 0, ciphertextBytes, 0, ciphertextBytes.length);
        System.arraycopy(encodedBytes, ciphertextBytes.length, authTag, 0, authTag.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, authTag);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);

        return new String(cipher.doFinal(ciphertextBytes), StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            SymmetricEncryptionGCM3 encryptor = new SymmetricEncryptionGCM3();
            String plaintext = "This is a secret message!";

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}