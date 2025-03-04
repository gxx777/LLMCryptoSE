import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AsymmetricEncryption4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public AsymmetricEncryption4() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public void encryptSymmetricKey(String symmetricKeyFile, String encryptedKeyFile) throws Exception {
        // Generate a symmetric key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey symmetricKey = keyGenerator.generateKey();

        // Encrypt the symmetric key using the asymmetric algorithm
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSymmetricKey = encryptCipher.doFinal(symmetricKey.getEncoded());

        // Write the encrypted symmetric key to a file
        try (FileOutputStream outputStream = new FileOutputStream(encryptedKeyFile)) {
            outputStream.write(encryptedSymmetricKey);
        }
    }

    public void decryptSymmetricKey(String encryptedKeyFile, String decryptedKeyFile) throws Exception {
        // Read the encrypted symmetric key from the file
        byte[] encryptedSymmetricKey;
        try (FileInputStream inputStream = new FileInputStream(encryptedKeyFile)) {
            encryptedSymmetricKey = new byte[inputStream.available()];
            inputStream.read(encryptedSymmetricKey);
        }

        // Decrypt the symmetric key using the asymmetric algorithm
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSymmetricKey = decryptCipher.doFinal(encryptedSymmetricKey);

        // Create a SecretKeySpec for the decrypted symmetric key
        SecretKey secretKey = new SecretKeySpec(decryptedSymmetricKey, "AES");

        // Write the decrypted symmetric key to a file
        try (FileOutputStream outputStream = new FileOutputStream(decryptedKeyFile)) {
            outputStream.write(secretKey.getEncoded());
        }
    }

    public static void main(String[] args) {
        try {
            AsymmetricEncryption4 encryption = new AsymmetricEncryption4();

            // Encrypt the symmetric key
            encryption.encryptSymmetricKey("symmetricKey.txt", "encryptedSymmetricKey.txt");

            // Decrypt the symmetric key
            encryption.decryptSymmetricKey("encryptedSymmetricKey.txt", "decryptedSymmetricKey.txt");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}