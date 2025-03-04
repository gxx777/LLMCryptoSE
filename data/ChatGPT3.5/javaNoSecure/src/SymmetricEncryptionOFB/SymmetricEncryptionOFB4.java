import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricEncryptionOFB4 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/OFB/PKCS5Padding";

    private SecretKeySpec secretKey;
    private IvParameterSpec ivParameterSpec;

    public SymmetricEncryptionOFB4(byte[] key, byte[] iv) {
        secretKey = new SecretKeySpec(key, ALGORITHM);
        ivParameterSpec = new IvParameterSpec(iv);
    }

    public byte[] encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(data.getBytes());
    }

    public byte[] decrypt(byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(encryptedData);
    }

    public static void main(String[] args) {
        try {
            byte[] key = "1234567890123456".getBytes(); // 16 byte key
            byte[] iv = "1234567890123456".getBytes(); // 16 byte IV

            SymmetricEncryptionOFB4 symmetricEncryption = new SymmetricEncryptionOFB4(key, iv);

            String data = "Hello, World!";
            byte[] encryptedData = symmetricEncryption.encrypt(data);
            System.out.println("Encrypted data: " + new String(encryptedData));

            byte[] decryptedData = symmetricEncryption.decrypt(encryptedData);
            System.out.println("Decrypted data: " + new String(decryptedData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}