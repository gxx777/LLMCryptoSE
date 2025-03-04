import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;

public class AsymmetricEncryption4 {
    public static void main(String[] args) {
        try {
            // Generate asymmetric key pair
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Generate symmetric key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();

            // Encrypt symmetric key using asymmetric algorithm
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedKey = rsaCipher.doFinal(secretKey.getEncoded());

            // Write encrypted key to file
            FileOutputStream keyOut = new FileOutputStream("encryptedKey.txt");
            keyOut.write(encryptedKey);
            keyOut.close();

            // Decrypt symmetric key using private key
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedKey = rsaCipher.doFinal(encryptedKey);

            // Reconstruct symmetric key
            SecretKey reconstructedKey = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");

            // Print original and reconstructed keys
            System.out.println("Original Key: " + secretKey);
            System.out.println("Reconstructed Key: " + reconstructedKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}