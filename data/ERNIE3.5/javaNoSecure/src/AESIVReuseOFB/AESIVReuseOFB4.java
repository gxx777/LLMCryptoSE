import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseOFB4 {

    private static final String ALGORITHM = "AES/OFB/NoPadding";
    private static final byte[] KEY = "ThisIsASecretKey12345678".getBytes(StandardCharsets.UTF_8); // 16 bytes key
    private static final byte[] INIT_VECTOR = "ThisIsAnIV12345678".getBytes(StandardCharsets.UTF_8); // 16 bytes IV

    public static void main(String[] args) throws Exception {
        String message1 = "Hello, World!";
        String message2 = "This is a second message.";
        String message3 = "And the third one.";

        // Encrypt messages
        String encrypted1 = encrypt(message1);
        String encrypted2 = encrypt(message2);
        String encrypted3 = encrypt(message3);

        // Decrypt messages
        String decrypted1 = decrypt(encrypted1);
        String decrypted2 = decrypt(encrypted2);
        String decrypted3 = decrypt(encrypted3);

        // Output results
        System.out.println("Original messages:");
        System.out.println(message1);
        System.out.println(message2);
        System.out.println(message3);

        System.out.println("\nEncrypted messages:");
        System.out.println(encrypted1);
        System.out.println(encrypted2);
        System.out.println(encrypted3);

        System.out.println("\nDecrypted messages:");
        System.out.println(decrypted1);
        System.out.println(decrypted2);
        System.out.println(decrypted3);
    }

    public static String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(INIT_VECTOR);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(INIT_VECTOR);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");

        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText));

        return new String(decrypted, StandardCharsets.UTF_8);
    }
}