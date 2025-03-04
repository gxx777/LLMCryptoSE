import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESIVReuseCBC1 {

    private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final byte[] KEY = "MySuperSecretKeyThisShouldBe32BytesLong".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "MySuperIVThisShouldBe16BytesLong".getBytes(StandardCharsets.UTF_8);

    public static String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText));

        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
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
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}