import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;

public class SymmetricEncryptionCTR2 {

    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final byte[] KEY = "MySecretKey".getBytes(StandardCharsets.UTF_8);
    private static final byte[] INIT_VECTOR = new byte[16]; // CTR mode doesn't require an initialization vector

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public static String encrypt(String value) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(INIT_VECTOR);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] encryptedValue = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedValue);
    }

    public static String decrypt(String encryptedValue) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(INIT_VECTOR);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decryptedValue = cipher.doFinal(Base64.getDecoder().decode(encryptedValue));
        return new String(decryptedValue, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            String originalValue = "Hello, World!";
            String encryptedValue = encrypt(originalValue);
            String decryptedValue = decrypt(encryptedValue);

            System.out.println("Original Value: " + originalValue);
            System.out.println("Encrypted Value: " + encryptedValue);
            System.out.println("Decrypted Value: " + decryptedValue);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}