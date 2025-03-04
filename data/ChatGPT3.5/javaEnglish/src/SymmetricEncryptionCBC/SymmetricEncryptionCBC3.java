import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SymmetricEncryptionCBC3 {

    private static final String AES_ALGORITHM = "AES";
    private static final String AES_CIPHER_MODE = "AES/CBC/PKCS5Padding";
    private static final String INIT_VECTOR = "abcdefghijklmnop";

    private static SecretKeySpec secretKey;
    private static IvParameterSpec ivParameterSpec;

    public SymmetricEncryptionCBC3(byte[] key) {
        secretKey = new SecretKeySpec(key, AES_ALGORITHM);
        ivParameterSpec = new IvParameterSpec(INIT_VECTOR.getBytes());
    }

    public String encrypt(String input) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String encryptedInput) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_MODE);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedInput));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        byte[] key = "symmetric_key".getBytes();
        SymmetricEncryptionCBC3 symmetricEncryption = new SymmetricEncryptionCBC3(key);

        String originalString = "Hello, world!";
        String encryptedString = symmetricEncryption.encrypt(originalString);
        System.out.println("Encrypted: " + encryptedString);

        String decryptedString = symmetricEncryption.decrypt(encryptedString);
        System.out.println("Decrypted: " + decryptedString);
    }
}