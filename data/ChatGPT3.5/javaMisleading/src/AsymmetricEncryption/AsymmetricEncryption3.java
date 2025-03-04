import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;

public class AsymmetricEncryption3 {

    private static final String ALGORITHM = "RSA";
    private static final String SYMMETRIC_ALGORITHM = "AES";
    private static final int KEY_SIZE = 2048;

    public static void generateKeyPair(String publicKeyPath, String privateKeyPath) throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();

        Files.write(Paths.get(publicKeyPath), publicKeyBytes);
        Files.write(Paths.get(privateKeyPath), privateKeyBytes);
    }

    public static byte[] encryptWithPublicKey(String publicKeyPath, byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        PublicKey publicKey = KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(Files.readAllBytes(Paths.get(publicKeyPath))));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] decryptWithPrivateKey(String privateKeyPath, byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        PrivateKey privateKey = KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(Paths.get(privateKeyPath))));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static void main(String[] args) {
        String publicKeyPath = "publicKey.pem";
        String privateKeyPath = "privateKey.pem";
        String symmetricKeyPath = "symmetricKey.dat";
        
        try {
            generateKeyPair(publicKeyPath, privateKeyPath);
            
            // Generate a symmetric key
            KeyGenerator keyGenerator = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
            keyGenerator.init(256);
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] symmetricKeyEncoded = secretKey.getEncoded();
            
            // Encrypt symmetric key with public key
            byte[] encryptedSymmetricKey = encryptWithPublicKey(publicKeyPath, symmetricKeyEncoded);
            Files.write(Paths.get(symmetricKeyPath), encryptedSymmetricKey);
            
            // Decrypt symmetric key with private key
            byte[] decryptedSymmetricKey = decryptWithPrivateKey(privateKeyPath, encryptedSymmetricKey);
            
            // Your code for using the decrypted symmetric key goes here
            
            System.out.println("Encryption and decryption of symmetric key using asymmetric encryption done successfully!");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}