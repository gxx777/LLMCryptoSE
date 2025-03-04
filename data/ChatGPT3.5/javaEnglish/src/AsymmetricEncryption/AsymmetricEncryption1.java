import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class AsymmetricEncryption1 {

    public static void main(String[] args) throws Exception {
        
        // Generate a RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // Get public and private keys
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        
        // Generate symmetric key
        KeyGenerator keyGenSymmetric = KeyGenerator.getInstance("AES");
        keyGenSymmetric.init(128);
        SecretKey secretKey = keyGenSymmetric.generateKey();
        
        // Encrypt symmetric key using public key
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(secretKey.getEncoded());
        
        // Save encrypted key to file
        FileOutputStream keyOut = new FileOutputStream("encryptedKey.bin");
        keyOut.write(encryptedKey);
        keyOut.close();
        
        // Decrypt symmetric key using private key
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKey = cipher.doFinal(encryptedKey);
        
        // Reconstruct symmetric key
        SecretKey decryptedSecretKey = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");
        
        System.out.println("Symmetric key encryption and decryption successful!");
    }

}