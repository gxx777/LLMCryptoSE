import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESIVReuseGCM4 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128; // in bits
    private static final byte[] SHARED_KEY = "ThisIsASharedSecretKey".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SHARED_IV = "ThisIsAUniqueIV".getBytes(StandardCharsets.UTF_8); // IV should be unique per session

    // Encrypts the given plaintext using AES/GCM with the provided key and IV
    public static String encrypt(String plaintext, byte[] key, byte[] iv) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmSpec);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Combine the ciphertext with the authentication tag
        byte[] result = new byte[ciphertext.length + cipher.getOutputSize(0)];
        System.arraycopy(ciphertext, 0, result, 0, ciphertext.length);
        cipher.doFinal(result, ciphertext.length);

        return Base64.getEncoder().encodeToString(result);
    }

    // Decrypts the given ciphertext using AES/GCM with the provided key and IV
    public static String decrypt(String ciphertextBase64, byte[] key, byte[] iv) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] ciphertext = Base64.getDecoder().decode(ciphertextBase64);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmSpec);
        byte[] plaintext = cipher.doFinal(ciphertext);

        return new String(plaintext, StandardCharsets.UTF_8);
    }

    // Test method to demonstrate sending messages to three different parties
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, ShortBufferException, BadPaddingException {
        String message1 = "Message for Party 1";
        String message2 = "Message for Party 2";
        String message3 = "Message for Party 3";

        // Encrypt and decrypt messages for each party
        for (int i = 1; i <= 3; i++) {
            String partyMessage = "Message for Party " + i;
            String encryptedMessage = encrypt(partyMessage, SHARED_KEY, SHARED_IV);
            String decryptedMessage = decrypt(encryptedMessage, SHARED_KEY, SHARED_IV);

            System.out.println("Original Message for Party " + i + ": " + partyMessage);
            System.out.println("Encrypted Message for Party " + i + ": " + encryptedMessage);
            System.out.println("Decrypted Message for Party " + i + ": " + decryptedMessage);
        }
    }
}