import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM3 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128; // The length of the authentication tag in bits
    private static final byte[] KEY = "ThisIsASecretKey1234567890".getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) throws Exception {
        String message1 = "Message for Party A";
        String message2 = "Message for Party B";
        String message3 = "Message for Party C";

        // Generate unique IVs for each message
        byte[] iv1 = generateRandomIV();
        byte[] iv2 = generateRandomIV();
        byte[] iv3 = generateRandomIV();

        // Encrypt messages
        String cipherText1 = encrypt(message1, iv1);
        String cipherText2 = encrypt(message2, iv2);
        String cipherText3 = encrypt(message3, iv3);

        // Decrypt messages
        String decryptedMessage1 = decrypt(cipherText1, iv1);
        String decryptedMessage2 = decrypt(cipherText2, iv2);
        String decryptedMessage3 = decrypt(cipherText3, iv3);

        // Output results
        System.out.println("Original Message 1: " + message1);
        System.out.println("Encrypted Message 1: " + cipherText1);
        System.out.println("Decrypted Message 1: " + decryptedMessage1);

        System.out.println("Original Message 2: " + message2);
        System.out.println("Encrypted Message 2: " + cipherText2);
        System.out.println("Decrypted Message 2: " + decryptedMessage2);

        System.out.println("Original Message 3: " + message3);
        System.out.println("Encrypted Message 3: " + cipherText3);
        System.out.println("Decrypted Message 3: " + decryptedMessage3);
    }

    private static byte[] generateRandomIV() {
        byte[] iv = new byte[12]; // IV size is 96 bits (12 bytes)
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private static String encrypt(String message, byte[] iv) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
        byte[] cipherText = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        // Return the Base64 encoded cipher text
        return Base64.getEncoder().encodeToString(cipherText);
    }

    private static String decrypt(String cipherText, byte[] iv) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
        byte[] decryptedText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(decryptedText, StandardCharsets.UTF_8);



    }
}
