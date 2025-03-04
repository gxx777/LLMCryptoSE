import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCFB4 {
    private static final String ALGORITHM = "AES/CFB8/NoPadding";
    private static final int IV_SIZE = 16;

    public static String encrypt(String key, String value) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(value.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String key, String encrypted) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);
        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
        return new String(original);
    }

    public static void main(String[] args) throws Exception {
        String key = "Bar12345Bar12345"; // 128 bit key
        String message1 = "Hello from party 1";
        String message2 = "Hello from party 2";
        String message3 = "Hello from party 3";

        String encrypted1 = encrypt(key, message1);
        String encrypted2 = encrypt(key, message2);
        String encrypted3 = encrypt(key, message3);

        System.out.println("Encrypted message from party 1: " + encrypted1);
        System.out.println("Encrypted message from party 2: " + encrypted2);
        System.out.println("Encrypted message from party 3: " + encrypted3);

        System.out.println("Decrypted message from party 1: " + decrypt(key, encrypted1));
        System.out.println("Decrypted message from party 2: " + decrypt(key, encrypted2));
        System.out.println("Decrypted message from party 3: " + decrypt(key, encrypted3));
    }
}