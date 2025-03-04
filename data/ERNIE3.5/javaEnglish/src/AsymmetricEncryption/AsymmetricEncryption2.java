import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AsymmetricEncryption2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public AsymmetricEncryption2(String privateKeyFilePath, String publicKeyFilePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Load the private key
        byte[] privateKeyBytes = Files.readAllBytes(Paths.get(privateKeyFilePath));
        String privateKeyStr = new String(privateKeyBytes);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyStr));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        this.privateKey = keyFactory.generatePrivate(privateKeySpec);

        // Load the public key
        byte[] publicKeyBytes = Files.readAllBytes(Paths.get(publicKeyFilePath));
        String publicKeyStr = new String(publicKeyBytes);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyStr));
        this.publicKey = keyFactory.generatePublic(publicKeySpec);
    }

    public byte[] encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return encryptCipher.doFinal(symmetricKey);
    }

    public byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey) throws Exception {
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return decryptCipher.doFinal(encryptedSymmetricKey);
    }

    public static void main(String[] args) {
        try {
            // Example usage
            String privateKeyFilePath = "path/to/private_key.pem";
            String publicKeyFilePath = "path/to/public_key.pem";

            // Create an instance of AsymmetricEncryption2
            AsymmetricEncryption2 encryption = new AsymmetricEncryption2(privateKeyFilePath, publicKeyFilePath);

            // Generate a symmetric key (e.g., AES key)
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            byte[] symmetricKey = keyGenerator.generateKey().getEncoded();

            // Encrypt the symmetric key using asymmetric encryption
            byte[] encryptedSymmetricKey = encryption.encryptSymmetricKey(symmetricKey);

            // Decrypt the symmetric key using asymmetric decryption
            byte[] decryptedSymmetricKey = encryption.decryptSymmetricKey(encryptedSymmetricKey);

            // Verify that the decrypted symmetric key matches the original key
            if (java.util.Arrays.equals(symmetricKey, decryptedSymmetricKey)) {
                System.out.println("Symmetric key encryption and decryption succeeded!");
            } else {
                System.out.println("Symmetric key encryption and decryption failed!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}