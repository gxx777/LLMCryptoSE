import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

public class RSAEncryption2 {
    private static final int KEY_SIZE = 2048;
    private static final String RSA = "RSA";
    private static final String AES = "AES";
    private static final String PADDING = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(PADDING);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            // Generate key pair
            KeyPair keyPair = generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Encrypt the symmetric key
            String symmetricKey = "ThisIsASymmetricKey";
            String encryptedSymmetricKey = encrypt(symmetricKey, publicKey);
            System.out.println("Encrypted symmetric key: " + encryptedSymmetricKey);

            // Decrypt the symmetric key
            String decryptedSymmetricKey = decrypt(encryptedSymmetricKey, privateKey);
            System.out.println("Decrypted symmetric key: " + decryptedSymmetricKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}