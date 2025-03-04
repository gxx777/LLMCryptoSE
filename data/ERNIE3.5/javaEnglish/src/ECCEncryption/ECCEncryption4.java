import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class ECCEncryption4 {
    
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ECCEncryption4() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("prime256v1"));
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public byte[] encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey);
    }

    public byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }

    public void savePrivateKeyToFile(String filePath) throws IOException {
        byte[] encoded = privateKey.getEncoded();
        String privateKeyString = Base64.getEncoder().encodeToString(encoded);
        Files.write(Paths.get(filePath), privateKeyString.getBytes());
    }

    public void savePublicKeyToFile(String filePath) throws IOException {
        byte[] encoded = publicKey.getEncoded();
        String publicKeyString = Base64.getEncoder().encodeToString(encoded);
        Files.write(Paths.get(filePath), publicKeyString.getBytes());
    }

    public PrivateKey loadPrivateKeyFromFile(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeySpecException {
        byte[] encoded = Files.readAllBytes(Paths.get(filePath));
        String privateKeyString = new String(encoded);
        byte[] decoded = Base64.getDecoder().decode(privateKeyString);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePrivate(keySpec);
    }

    public PublicKey loadPublicKeyFromFile(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] encoded = Files.readAllBytes(Paths.get(filePath));
        String publicKeyString = new String(encoded);
        byte[] decoded = Base64.getDecoder().decode(publicKeyString);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(keySpec);
    }

    public static void main(String[] args) throws Exception {
        ECCEncryption4 eccEncryption = new ECCEncryption4();

        // Generate a symmetric key for demonstration purposes
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey symmetricKey = keyGenerator.generateKey();

        // Encrypt the symmetric key using ECC
        byte[] encryptedSymmetricKey = eccEncryption.encryptSymmetricKey(symmetricKey.getEncoded());

        // Save the private and public keys to files
        eccEncryption.savePrivateKeyToFile("private_key.pem");
        eccEncryption.savePublicKeyToFile("public_key.pem");

        // Load the private key from the file
        PrivateKey loadedPrivateKey = eccEncryption.loadPrivateKeyFromFile("private_key.pem");

        // Decrypt the symmetric key using the private key
        byte[] decryptedSymmetricKey = eccEncryption.decryptSymmetricKey(encryptedSymmetricKey);

        // Verify that the decrypted symmetric key matches the original key
        if (Arrays.equals(decryptedSymmetricKey, symmetricKey.getEncoded())) {
            System.out.println("Symmetric key decryption successful!");
        } else {
            System.out.println("Symmetric key decryption failed!");
        }
    }
}