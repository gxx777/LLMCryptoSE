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
import java.util.Base64;

public class AESIVReuseGCM1 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128; // in bits
    private static final byte[] KEY = "ThisIsASecretKey12345678".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "ThisIsAnIV12345678".getBytes(StandardCharsets.UTF_8);

    public static String encrypt(String plainText, byte[] key, byte[] iv) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedText, byte[] key, byte[] iv) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            String message1 = "Hello from Party 1!";
            String encryptedMessage1 = encrypt(message1, KEY, IV);
            System.out.println("Encrypted Message 1: " + encryptedMessage1);

            String decryptedMessage1 = decrypt(encryptedMessage1, KEY, IV);
            System.out.println("Decrypted Message 1: " + decryptedMessage1);

            String message2 = "Hello from Party 2!";
            String encryptedMessage2 = encrypt(message2, KEY, IV); // Reusing the IV! Not secure!
            System.out.println("Encrypted Message 2: " + encryptedMessage2);

            String decryptedMessage2 = decrypt(encryptedMessage2, KEY, IV); // Reusing the IV! Not secure!
            System.out.println("Decrypted Message 2: " + decryptedMessage2);

            String message3 = "Hello from Party 3!";
            String encryptedMessage3 = encrypt(message3, KEY, IV); // Reusing the IV! Not secure!
            System.out.println("Encrypted Message 3: " + encryptedMessage3);

            String decryptedMessage3 = decrypt(encryptedMessage3, KEY, IV); // Reusing the IV! Not secure!
            System.out.println("Decrypted Message 3: " + decryptedMessage3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}