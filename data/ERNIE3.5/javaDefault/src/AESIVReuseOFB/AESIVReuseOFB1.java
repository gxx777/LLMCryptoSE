import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseOFB1 {

    private static final String ALGORITHM = "AES/OFB/NoPadding";
    private static final byte[] KEY = "ThisIsASecretKey".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "ThisIsAnIV".getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) throws Exception {
        String message1 = "Hello, World!";
        String message2 = "This is a second message.";
        String message3 = "And this is the third one.";

        String encrypted1 = encrypt(message1);
        String encrypted2 = encrypt(message2);
        String encrypted3 = encrypt(message3);

        System.out.println("Encrypted Message 1: " + encrypted1);
        System.out.println("Encrypted Message 2: " + encrypted2);
        System.out.println("Encrypted Message 3: " + encrypted3);

        String decrypted1 = decrypt(encrypted1);
        String decrypted2 = decrypt(encrypted2);
        String decrypted3 = decrypt(encrypted3);

        System.out.println("Decrypted Message 1: " + decrypted1);
        System.out.println("Decrypted Message 2: " + decrypted2);
        System.out.println("Decrypted Message 3: " + decrypted3);
    }

    public static String encrypt(String message) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encrypted) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decoded = Base64.getDecoder().decode(encrypted);
        byte[] decrypted = cipher.doFinal(decoded);

        return new String(decrypted, StandardCharsets.UTF_8);
    }
}