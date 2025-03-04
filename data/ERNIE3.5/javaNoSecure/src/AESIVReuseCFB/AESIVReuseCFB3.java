import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCFB3 {

    private static final String ALGORITHM = "AES/CFB/NoPadding";
    private static final byte[] KEY = "MySecretKey".getBytes(StandardCharsets.UTF_8); // 16 bytes key for AES-128
    private static final byte[] IV = "MyInitVector".getBytes(StandardCharsets.UTF_8); // 8 bytes IV for CFB mode

    public static void main(String[] args) throws Exception {
        String[] messages = {
            "Message 1 from Party A",
            "Message 2 from Party B",
            "Message 3 from Party C"
        };

        for (String message : messages) {
            byte[] encrypted = encrypt(message.getBytes(StandardCharsets.UTF_8));
            System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(encrypted));

            byte[] decrypted = decrypt(encrypted);
            System.out.println("Decrypted: " + new String(decrypted, StandardCharsets.UTF_8));
        }
    }

    public static byte[] encrypt(byte[] data) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] encrypted) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        return cipher.doFinal(encrypted);
    }
}