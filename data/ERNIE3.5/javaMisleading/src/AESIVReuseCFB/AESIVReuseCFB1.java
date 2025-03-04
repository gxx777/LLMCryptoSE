import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCFB1 {

    private static final String KEY = "ThisIsASecretKey"; // 16 bytes key for AES
    private static final String IV = "ThisIsAnIV"; // 8 bytes IV for CFB mode

    public static String encrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes(StandardCharsets.UTF_8));

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes(StandardCharsets.UTF_8));

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        String message1 = "Hello from Party A";
        String message2 = "Hello from Party B";
        String message3 = "Hello from Party C";

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
}