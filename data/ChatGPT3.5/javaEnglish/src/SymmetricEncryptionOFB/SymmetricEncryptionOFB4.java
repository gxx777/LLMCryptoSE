import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SymmetricEncryptionOFB4 {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "OFB";
    private static final String PADDING = "NoPadding";

    private SecretKeySpec secretKey;

    public SymmetricEncryptionOFB4(byte[] key) {
        this.secretKey = new SecretKeySpec(key, ALGORITHM);
    }

    public String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedBytes = Base64.getDecoder().decode(ciphertext);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        byte[] key = "secretkeysecret".getBytes();
        SymmetricEncryptionOFB4 symmetricEncryption = new SymmetricEncryptionOFB4(key);

        String plaintext = "Hello, world!";
        String ciphertext = symmetricEncryption.encrypt(plaintext);
        System.out.println("Encrypted: " + ciphertext);

        String decryptedtext = symmetricEncryption.decrypt(ciphertext);
        System.out.println("Decrypted: " + decryptedtext);
    }
}