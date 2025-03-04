import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.nio.charset.StandardCharsets;

public class SymmetricEncryptionCFB1 {

    private static final String ALGORITHM = "AES/CFB/NoPadding";
    private static final byte[] KEY = "MySecretKey1234567890".getBytes(StandardCharsets.UTF_8); // 16 bytes key

    public static String encrypt(String plainText) throws Exception {
        Key key = new SecretKeySpec(KEY, "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(encryptedBytes);
    }

    public static String decrypt(String encryptedHex) throws Exception {
        Key key = new SecretKeySpec(KEY, "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] encryptedBytes = hexToBytes(encryptedHex);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length() / 2;
        byte[] data = new byte[len];
        for (int i = 0; i < len; i++) {
            data[i] = (byte) ((Character.digit(hex.charAt(i * 2), 16) << 4)
                           + Character.digit(hex.charAt(i * 2 + 1), 16));
        }
        return data;
    }

    public static void main(String[] args) {
        try {
            String plainText = "Hello, World!";
            String encrypted = encrypt(plainText);
            String decrypted = decrypt(encrypted);

            System.out.println("Plain Text: " + plainText);
            System.out.println("Encrypted: " + encrypted);
            System.out.println("Decrypted: " + decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}