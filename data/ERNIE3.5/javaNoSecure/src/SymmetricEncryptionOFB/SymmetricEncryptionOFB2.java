import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;

public class SymmetricEncryptionOFB2 {

    private static final String ALGORITHM = "AES/OFB/NoPadding";

    public String encrypt(String plainText, String secretKey, String iv) throws Exception {
        Key aesKey = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decrypt(String encryptedText, String secretKey, String iv) throws Exception {
        Key aesKey = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(original, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            SymmetricEncryptionOFB2 encryptor = new SymmetricEncryptionOFB2();

            String plainText = "Hello, World!";
            String secretKey = "MySecretKey";
            String iv = "MyIV";

            String encrypted = encryptor.encrypt(plainText, secretKey, iv);
            System.out.println("Encrypted Text: " + encrypted);

            String decrypted = encryptor.decrypt(encrypted, secretKey, iv);
            System.out.println("Decrypted Text: " + decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}