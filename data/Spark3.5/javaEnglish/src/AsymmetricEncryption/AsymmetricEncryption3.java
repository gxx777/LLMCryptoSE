import java.security.*;
import javax.crypto.*;
import java.io.*;

public class AsymmetricEncryption3 {
    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Encrypt the symmetric key
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSymmetricKey = cipher.doFinal("This is a symmetric key".getBytes());

        // Decrypt the symmetric key
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSymmetricKey = cipher.doFinal(encryptedSymmetricKey);

        // Print the decrypted symmetric key
        System.out.println("Decrypted symmetric key: " + new String(decryptedSymmetricKey));
    }
}