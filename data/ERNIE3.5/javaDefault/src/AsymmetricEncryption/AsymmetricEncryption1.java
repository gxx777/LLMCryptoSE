import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

public class AsymmetricEncryption1 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public AsymmetricEncryption1() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public byte[] encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey);
    }

    public byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }

    public void storeSymmetricKey(byte[] symmetricKey, String filePath) throws IOException, Exception {
        byte[] encryptedSymmetricKey = encryptSymmetricKey(symmetricKey);
        Files.write(Paths.get(filePath), encryptedSymmetricKey);
    }

    public byte[] retrieveSymmetricKey(String filePath) throws IOException, Exception {
        byte[] encryptedSymmetricKey = Files.readAllBytes(Paths.get(filePath));
        return decryptSymmetricKey(encryptedSymmetricKey);
    }

    public static void main(String[] args) {
        try {
            AsymmetricEncryption1 aes = new AsymmetricEncryption1();

            // Generate a symmetric key (for example, AES key)
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey symmetricKey = keyGenerator.generateKey();

            // Store the symmetric key encrypted with RSA
            String filePath = "encrypted_symmetric_key.bin";
            aes.storeSymmetricKey(symmetricKey.getEncoded(), filePath);

            // Retrieve and decrypt the symmetric key
            byte[] decryptedSymmetricKey = aes.retrieveSymmetricKey(filePath);
            SecretKey retrievedSymmetricKey = new SecretKeySpec(decryptedSymmetricKey, "AES");

            // Now you can use the retrievedSymmetricKey for symmetric encryption/decryption

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}