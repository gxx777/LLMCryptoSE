import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.*;

public class RSAEncryption1 {
    public static void main(String[] args) throws Exception {
        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Generate symmetric key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();

        // Encrypt symmetric key with RSA public key
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(secretKey.getEncoded());

        // Save encrypted symmetric key to file
        Files.write(Paths.get("encrypted_key"), encryptedKey);

        // Decrypt symmetric key with RSA private key
        byte[] encryptedKeyFromFile = Files.readAllBytes(Paths.get("encrypted_key"));
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKey = cipher.doFinal(encryptedKeyFromFile);

        // Use decrypted key to perform encryption and decryption with AES algorithm
        SecretKey decryptedSecretKey = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");
        // Now you can use decryptedSecretKey to encrypt and decrypt data with AES algorithm
    }
}