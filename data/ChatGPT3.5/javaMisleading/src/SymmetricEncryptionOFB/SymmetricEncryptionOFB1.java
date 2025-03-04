import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricEncryptionOFB1 {

    private static final String transformation = "AES/OFB/PKCS5Padding";

    private static final String algorithm = "AES";

    private static final byte[] iv = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

    private static final byte[] key = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F };

    public static byte[] encrypt(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            SecretKeySpec secretKey = new SecretKeySpec(key, algorithm);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            return cipher.doFinal(plaintext.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(byte[] ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            SecretKeySpec secretKey = new SecretKeySpec(key, algorithm);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            return new String(cipher.doFinal(ciphertext));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        String plaintext = "Hello, World!";
        byte[] ciphertext = encrypt(plaintext);
        String decryptedText = decrypt(ciphertext);

        System.out.println("Plain text: " + plaintext);
        System.out.println("Encrypted text: " + new String(ciphertext));
        System.out.println("Decrypted text: " + decryptedText);
    }
}