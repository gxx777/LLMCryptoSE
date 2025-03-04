import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class SymmetricEncryptionCTR1 {

    private static final byte[] keyBytes = "abcdefghijklmnop".getBytes(StandardCharsets.UTF_8);
    private static final byte[] ivBytes = "1234567890123456".getBytes(StandardCharsets.UTF_8);

    public static byte[] encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        return cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
    }

    public static String decrypt(byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        String plaintext = "Hello, world!";
        byte[] encrypted = encrypt(plaintext);
        String decrypted = decrypt(encrypted);

        System.out.println("Original plaintext: " + plaintext);
        System.out.println("Encrypted ciphertext: " + new String(encrypted, StandardCharsets.UTF_8));
        System.out.println("Decrypted plaintext: " + decrypted);
    }
}