import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricEncryptionOFB2 {

    private static final String TRANSFORMATION = "AES/OFB/PKCS5Padding";
    private static final String ALGORITHM = "AES";

    private static final byte[] IV = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    private SecretKeySpec secretKey;

    public SymmetricEncryptionOFB2(byte[] key) {
        secretKey = new SecretKeySpec(key, ALGORITHM);
    }

    public byte[] encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(IV));
        return cipher.doFinal(plainText.getBytes());
    }

    public String decrypt(byte[] cipherText) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IV));
        byte[] result = cipher.doFinal(cipherText);
        return new String(result);
    }

    public static void main(String[] args) {
        try {
            String input = "Hello, World!";
            byte[] key = "thisisa16bytekey".getBytes();
            SymmetricEncryptionOFB2 encryptor = new SymmetricEncryptionOFB2(key);

            byte[] encrypted = encryptor.encrypt(input);
            System.out.println("Encrypted: " + new String(encrypted));

            String decrypted = encryptor.decrypt(encrypted);
            System.out.println("Decrypted: " + decrypted);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}