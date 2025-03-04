import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricEncryptionOFB2 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/OFB/PKCS5Padding";

    public static byte[] encrypt(String key, String initVector, String data) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKey secretKey = new SecretKeySpec(key.getBytes("UTF-8"), ALGORITHM);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

            return cipher.doFinal(data.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static byte[] decrypt(String key, String initVector, byte[] encryptedData) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKey secretKey = new SecretKeySpec(key.getBytes("UTF-8"), ALGORITHM);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

            return cipher.doFinal(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static void main(String[] args) {
        String key = "AESkey1234567890";
        String initVector = "OFBPassword12345";
        String data = "Hello, world!";

        byte[] encryptedData = encrypt(key, initVector, data);
        System.out.println("Encrypted data: " + new String(encryptedData));

        byte[] decryptedData = decrypt(key, initVector, encryptedData);
        System.out.println("Decrypted data: " + new String(decryptedData));
    }
}