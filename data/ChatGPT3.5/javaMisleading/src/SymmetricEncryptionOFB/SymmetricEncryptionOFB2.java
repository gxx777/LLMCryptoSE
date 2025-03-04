import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricEncryptionOFB2 {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/OFB/PKCS5Padding";

    private SecretKeySpec secretKey;
    private IvParameterSpec ivParameterSpec;

    public SymmetricEncryptionOFB2(byte[] key, byte[] iv) {
        secretKey = new SecretKeySpec(key, ALGORITHM);
        ivParameterSpec = new IvParameterSpec(iv);
    }

    public byte[] encrypt(String input) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(input.getBytes());
    }

    public String decrypt(byte[] input) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(input);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            String text = "Hello, world!";
            byte[] key = "1234567890123456".getBytes();
            byte[] iv = "9876543210987654".getBytes();

            SymmetricEncryptionOFB2 encryptor = new SymmetricEncryptionOFB2(key, iv);

            byte[] encrypted = encryptor.encrypt(text);
            System.out.println("Encrypted: " + new String(encrypted));

            String decrypted = encryptor.decrypt(encrypted);
            System.out.println("Decrypted: " + decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}