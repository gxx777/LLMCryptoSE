import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SymmetricEncryption3 {
    private static final String ALGORITHM = "AES";
    private static final String MODE = "ECB";
    private static final String PADDING = "PKCS5Padding";
    private static final String TRANSFORMATION = ALGORITHM + "/" + MODE + "/" + PADDING;

    private Key key;

    public SymmetricEncryption3(byte[] keyBytes) {
        this.key = new SecretKeySpec(keyBytes, ALGORITHM);
    }

    public byte[] encrypt(String plainText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            javax.crypto.BadPaddingException, javax.crypto.IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);

        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(plainText.getBytes());
    }

    public String decrypt(byte[] cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            javax.crypto.BadPaddingException, javax.crypto.IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);

        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] decryptedBytes = cipher.doFinal(cipherText);

        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            javax.crypto.BadPaddingException, javax.crypto.IllegalBlockSizeException {
        String text = "Hello, world!";
        byte[] keyBytes = "mysecretkey12345".getBytes();

        SymmetricEncryption3 symmetricEncryption3 = new SymmetricEncryption3(keyBytes);

        byte[] encryptedText = symmetricEncryption3.encrypt(text);
        System.out.println("Encrypted text: " + Base64.getEncoder().encodeToString(encryptedText));

        String decryptedText = symmetricEncryption3.decrypt(encryptedText);
        System.out.println("Decrypted text: " + decryptedText);
    }
}