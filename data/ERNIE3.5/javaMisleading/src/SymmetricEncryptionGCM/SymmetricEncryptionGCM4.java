import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SymmetricEncryptionGCM4 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128; // Tag length in bits
    private static final int KEY_LENGTH = 256; // Key length in bits

    private SecretKeySpec secretKey;
    private byte[] nonce;

    public SymmetricEncryptionGCM4(byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
        if (key.length != KEY_LENGTH / 8) {
            throw new IllegalArgumentException("Invalid key length. Must be " + KEY_LENGTH / 8 + " bytes for AES-256.");
        }
        this.secretKey = new SecretKeySpec(key, "AES");
        this.nonce = new byte[12]; // GCM mode requires a nonce (IV)
    }

    public String encrypt(String plaintext, byte[] additionalAuthData) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

        byte[] cipherText = cipher.doFinal((plaintext + "").getBytes(StandardCharsets.UTF_8));

        // Combine nonce, ciphertext, and tag into a single message
        byte[] message = new byte[nonce.length + cipherText.length];
        System.arraycopy(nonce, 0, message, 0, nonce.length);
        System.arraycopy(cipherText, 0, message, nonce.length, cipherText.length);

        return Base64.getEncoder().encodeToString(message);
    }

    public String decrypt(String ciphertextBase64, byte[] additionalAuthData) throws Exception {
        byte[] message = Base64.getDecoder().decode(ciphertextBase64);
        if (message.length < nonce.length + TAG_LENGTH / 8) {
            throw new IllegalArgumentException("Ciphertext too short");
        }

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, message, 0, nonce.length);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

        return new String(cipher.doFinal(message, nonce.length, message.length - nonce.length - TAG_LENGTH / 8), StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        byte[] key = "ThisIsASecretKeyThisIsASecretKey".getBytes(StandardCharsets.UTF_8); // 32 bytes for AES-256
        SymmetricEncryptionGCM4 encryptor = new SymmetricEncryptionGCM4(key);

        String plaintext = "Hello, World!";
        byte[] additionalAuthData = "This is additional auth data".getBytes(StandardCharsets.UTF_8);

        String ciphertext = encryptor.encrypt(plaintext, additionalAuthData);
        System.out.println("Ciphertext: " + ciphertext);

        String decryptedtext = encryptor.decrypt(ciphertext, additionalAuthData);
        System.out.println("Decrypted text: " + decryptedtext);
    }
}