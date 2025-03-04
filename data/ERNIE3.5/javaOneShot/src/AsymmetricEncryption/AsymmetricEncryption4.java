import javax.crypto.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class AsymmetricEncryption4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public AsymmetricEncryption4() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Use a key size of at least 2048 bits for RSA
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public byte[] encryptSymmetricKey(byte[] symmetricKey) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey);
    }

    public byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }

    public void savePrivateKeyToFile(String filePath) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKeyFromSpec = keyFactory.generatePrivate(pkcs8KeySpec);

        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(Base64.getEncoder().encode(privateKeyFromSpec.getEncoded()));
        }
    }

    public void loadPrivateKeyFromFile(String filePath) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException {
        byte[] keyBytes = Base64.getDecoder().decode(new String(Files.readAllBytes(Paths.get(filePath))));
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        this.privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
    }

    // Similar methods can be added for saving and loading the public key

    public static void main(String[] args) {
        try {
            AsymmetricEncryption4 encryptor = new AsymmetricEncryption4();

            // Generate a symmetric key for demonstration purposes
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128); // Use a key size appropriate for your needs
            SecretKey symmetricKey = keyGenerator.generateKey();

            // Encrypt the symmetric key using the public key
            byte[] encryptedSymmetricKey = encryptor.encryptSymmetricKey(symmetricKey.getEncoded());

            // Decrypt the symmetric key using the private key
            byte[] decryptedSymmetricKey = encryptor.decryptSymmetricKey(encryptedSymmetricKey);

            // Verify that the symmetric key was successfully decrypted
            if (Arrays.equals(symmetricKey.getEncoded(), decryptedSymmetricKey)) {
                System.out.println("Symmetric key was successfully encrypted and decrypted.");
            } else {
                System.out.println("Symmetric key decryption failed.");
            }

            // Save the private key to a file for later use
            encryptor.savePrivateKeyToFile("private_key.pem");

            // Load the private key from the file
            encryptor.loadPrivateKeyFromFile("private_key.pem");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}