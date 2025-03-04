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

public class AESIVReuseGCM3 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128; // Length of the authentication tag in bits
    private static final int KEY_SIZE = 256; // AES key size in bits
    private static final byte[] KEY = new byte[KEY_SIZE / 8]; // AES key
    private static final int IV_SIZE = 12; // GCM IV size in bytes

    // Initialize the AES key with random values
    static {
        // This is just an example. In real-world scenarios, you should use a secure random number generator.
        for (int i = 0; i < KEY.length; i++) {
            KEY[i] = (byte) (i ^ 0x5A); // Just using a simple XOR for demonstration
        }
    }

    public static String encryptMessageForParty1(String plainText) throws Exception {
        byte[] iv = generateRandomIV();
        return encryptMessage(plainText, iv);
    }

    public static String encryptMessageForParty2(String plainText) throws Exception {
        byte[] iv = generateRandomIV();
        return encryptMessage(plainText, iv);
    }

    public static String encryptMessageForParty3(String plainText) throws Exception {
        byte[] iv = generateRandomIV();
        return encryptMessage(plainText, iv);
    }

    private static byte[] generateRandomIV() {
        byte[] iv = new byte[IV_SIZE];
        // Use a secure random number generator to populate the IV with random values
        // new SecureRandom().nextBytes(iv);
        // For demonstration purposes, we will just use a fixed IV (which is insecure in real-world usage)
        for (int i = 0; i < iv.length; i++) {
            iv[i] = (byte) i;
        }
        return iv;
    }

    private static String encryptMessage(String plainText, byte[] iv) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Combine the cipher text and the authentication tag
        byte[] result = new byte[cipherText.length + TAG_LENGTH / 8];
        System.arraycopy(cipherText, 0, result, 0, cipherText.length);
        System.arraycopy(cipher.getIV(), 0, result, cipherText.length, iv.length);

        // Return the Base64 encoded string
        return Base64.getEncoder().encodeToString(result);
    }

    public static void main(String[] args) {
        try {
            String messageForParty1 = "Message for Party 1";
            String encryptedForParty1 = encryptMessageForParty1(messageForParty1);
            System.out.println("Encrypted message for Party 1: " + encryptedForParty1);

            String messageForParty2 = "Message for Party 2";
            String encryptedForParty2 = encryptMessageForParty2(messageForParty2);
            System.out.println("Encrypted message for Party 2: " + encryptedForParty2);
            
            String messageForParty3 = "Message for Party 3";
            String encryptedForParty3 = encryptMessageForParty3(messageForParty3);
            System.out.println("Encrypted message for Party 3: " + encryptedForParty3);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}