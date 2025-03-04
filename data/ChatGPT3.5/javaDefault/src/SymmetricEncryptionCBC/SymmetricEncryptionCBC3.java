import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SymmetricEncryptionCBC3 {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    private SecretKey secretKey;
    private IvParameterSpec ivParameterSpec;

    public SymmetricEncryptionCBC3() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(256);
        secretKey = keyGenerator.generateKey();

        byte[] iv = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        ivParameterSpec = new IvParameterSpec(iv);
    }

    public byte[] encrypt(String input) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(input.getBytes());
    }

    public String decrypt(byte[] input) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(input);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        SymmetricEncryptionCBC3 symmetricEncryptionCBC3 = new SymmetricEncryptionCBC3();
        String plainText = "Hello, world!";
        System.out.println("Original: " + plainText);

        byte[] encrypted = symmetricEncryptionCBC3.encrypt(plainText);
        System.out.println("Encrypted: " + new String(encrypted));

        String decrypted = symmetricEncryptionCBC3.decrypt(encrypted);
        System.out.println("Decrypted: " + decrypted);
    }
}