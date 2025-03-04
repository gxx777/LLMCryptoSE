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
import java.security.SecureRandom;


public class AESIVReuseGCM2 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final byte[] KEY = "ThisIsASecretKeyThisIsASecretKey".getBytes(StandardCharsets.UTF_8); // 32 bytes for AES-256
    private static final int TAG_LENGTH = 128; // GCM Tag length in bits

    public static String encrypt(String plaintext, String associatedData) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, generateRandomIV());

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);

        byte[] ciphertext = cipher.doFinal((plaintext + associatedData).getBytes(StandardCharsets.UTF_8));

        // Combine the IV and the ciphertext
        byte[] ivCiphertext = new byte[gcmParameterSpec.getIV().length + ciphertext.length];
        System.arraycopy(gcmParameterSpec.getIV(), 0, ivCiphertext, 0, gcmParameterSpec.getIV().length);
        System.arraycopy(ciphertext, 0, ivCiphertext, gcmParameterSpec.getIV().length, ciphertext.length);

        return Base64.getEncoder().encodeToString(ivCiphertext);
    }

    public static String decrypt(String encryptedText, String associatedData) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
        byte[] ivCiphertext = Base64.getDecoder().decode(encryptedText);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, ivCiphertext, 0, ivCiphertext.length - 16);

        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);

        byte[] decryptedBytes = cipher.doFinal((associatedData).getBytes(StandardCharsets.UTF_8));

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private static byte[] generateRandomIV() {
        byte[] iv = new byte[12]; // AES GCM mode requires a 96-bit (12 byte) IV
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static void main(String[] args) {
        try {
            String plaintext = "Hello, World!";
            String associatedData = "Additional authenticated data";

            // Encrypt the message
            String encrypted = encrypt(plaintext, associatedData);
            System.out.println("Encrypted: " + encrypted);

            // Decrypt the message
            String decrypted = decrypt(encrypted, associatedData);
            System.out.println("Decrypted: " + decrypted);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}