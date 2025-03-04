import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCFB1 {

    // 注意：在实际应用中，密钥和IV应该是随机生成的，并且对于每次加密操作都应该是唯一的。
    // 下面为了示例目的，我们使用了固定的密钥和IV。
    private static final String KEY = "ThisIsASecretKey12345678"; // 16 bytes key for AES-128
    private static final String IV = "ThisIsAnIV12345678"; // 8 bytes IV for CFB mode

    public static String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV.getBytes(StandardCharsets.UTF_8));

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV.getBytes(StandardCharsets.UTF_8));

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            String message1 = "Hello from Party A!";
            String message2 = "Message from Party B!";
            String message3 = "Communication from Party C!";

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

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}