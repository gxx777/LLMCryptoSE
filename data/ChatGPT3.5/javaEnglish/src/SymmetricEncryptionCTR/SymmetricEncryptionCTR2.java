import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricEncryptionCTR2 {

    private static final String encryptionKey = "encryptionKey123";
    private static final String initializationVector = "initVector123456";

    public static byte[] encrypt(String plainText) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            SecretKey secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            return cipher.doFinal(plainText.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(byte[] cipherText) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            SecretKey secretKey = new SecretKeySpec(encryptionKey.getBytes(), "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            return new String(cipher.doFinal(cipherText));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        String originalString = "Hello, world!";
        System.out.println("Original String: " + originalString);

        byte[] encryptedString = encrypt(originalString);
        System.out.println("Encrypted String: " + new String(encryptedString));

        String decryptedString = decrypt(encryptedString);
        System.out.println("Decrypted String: " + decryptedString);
    }
}