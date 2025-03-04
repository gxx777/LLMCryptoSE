import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricEncryptionOFB3 {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "AES/OFB/NoPadding";
    private static final String IV = "0123456789abcdef";

    public static byte[] encrypt(String key, String data) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(MODE);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            return cipher.doFinal(data.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decrypt(String key, byte[] encryptedData) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(MODE);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            byte[] decryptedData = cipher.doFinal(encryptedData);
            return new String(decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        String key = "thisisaverysecretkey";
        String data = "Hello, World!";
        
        byte[] encryptedData = encrypt(key, data);
        System.out.println("Encrypted Data: " + new String(encryptedData));

        String decryptedData = decrypt(key, encryptedData);
        System.out.println("Decrypted Data: " + decryptedData);
    }
}