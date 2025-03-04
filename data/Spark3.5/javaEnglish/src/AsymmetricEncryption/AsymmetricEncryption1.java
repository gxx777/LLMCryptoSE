import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

public class AsymmetricEncryption1 {
    private static final String SYMMETRIC_KEY_FILE = "symmetric_key.txt";
    private static final String ENCRYPTED_SYMMETRIC_KEY_FILE = "encrypted_symmetric_key.txt";
    private static final String DECRYPTED_SYMMETRIC_KEY_FILE = "decrypted_symmetric_key.txt";

    public static void main(String[] args) throws Exception {
        // Generate a symmetric key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey symmetricKey = keyGen.generateKey();

        // Save the symmetric key to a file
        try (FileOutputStream fos = new FileOutputStream(SYMMETRIC_KEY_FILE)) {
            fos.write(symmetricKey.getEncoded());
        }

        // Generate an asymmetric key pair
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Encrypt the symmetric key using the public key
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSymmetricKey = cipher.doFinal(symmetricKey.getEncoded());

        // Save the encrypted symmetric key to a file
        try (FileOutputStream fos = new FileOutputStream(ENCRYPTED_SYMMETRIC_KEY_FILE)) {
            fos.write(encryptedSymmetricKey);
        }

        // Decrypt the symmetric key using the private key
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSymmetricKey = cipher.doFinal(encryptedSymmetricKey);

        // Save the decrypted symmetric key to a file
        try (FileOutputStream fos = new FileOutputStream(DECRYPTED_SYMMETRIC_KEY_FILE)) {
            fos.write(decryptedSymmetricKey);
        }
    }
}