import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SymmetricEncryptionCFB2 {

    private static final String ALGORITHM = "AES/CFB/NoPadding";
    private static final byte[] KEY = "ThisIsASecretKey".getBytes(StandardCharsets.UTF_8); // 替换为你自己的密钥
    private static final byte[] INIT_VECTOR = "ThisIsAnInitVector".getBytes(StandardCharsets.UTF_8); // 替换为你自己的初始化向量

    public static String encrypt(String valueToEnc) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR);
        SecretKeySpec skeySpec = new SecretKeySpec(KEY, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        byte[] encrypted = cipher.doFinal(valueToEnc.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encrypted) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR);
        SecretKeySpec skeySpec = new SecretKeySpec(KEY, "AES");

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));

        return new String(original);
    }

    public static void main(String[] args) {
        try {
            String original = "Hello, World!";
            System.out.println("Original String: " + original);

            String encrypted = encrypt(original);
            System.out.println("Encrypted String: " + encrypted);

            String decrypted = decrypt(encrypted);
            System.out.println("Decrypted String: " + decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}