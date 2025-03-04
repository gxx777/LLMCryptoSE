import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

public class RSAEncryption3 {
    private static final String RSA = "RSA";
    private static final int KEY_SIZE = 2048;
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

            // Encrypt and decrypt a symmetric key file
            String symmetricKeyFile = "This is a symmetric key file.";
            String encryptedSymmetricKeyFile = encrypt(symmetricKeyFile, publicKey);
            String decryptedSymmetricKeyFile = decrypt(encryptedSymmetricKeyFile, privateKey);

            System.out.println("Original symmetric key file: " + symmetricKeyFile);
            System.out.println("Encrypted symmetric key file: " + encryptedSymmetricKeyFile);
            System.out.println("Decrypted symmetric key file: " + decryptedSymmetricKeyFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}