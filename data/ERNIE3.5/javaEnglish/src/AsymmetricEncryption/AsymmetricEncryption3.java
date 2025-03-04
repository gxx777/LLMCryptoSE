import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;

public class AsymmetricEncryption3 {

    public static void main(String[] args) throws Exception {
        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Symmetric key to be encrypted and decrypted
        SecretKey symmetricKey = KeyGenerator.getInstance("AES").generateKey();

        // Encrypt the symmetric key using RSA
        byte[] encryptedSymmetricKey = encryptKey(symmetricKey.getEncoded(), publicKey);

        // Decrypt the symmetric key using RSA
        SecretKey decryptedSymmetricKey = decryptKey(encryptedSymmetricKey, privateKey);

        // Verify if the decrypted symmetric key matches the original key
        if (java.util.Arrays.equals(symmetricKey.getEncoded(), decryptedSymmetricKey.getEncoded())) {
            System.out.println("Symmetric key encryption and decryption succeeded!");
        } else {
            System.out.println("Symmetric key encryption and decryption failed!");
        }
    }

    public static byte[] encryptKey(byte[] key, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(key);
    }

    public static SecretKey decryptKey(byte[] encryptedKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKey = cipher.doFinal(encryptedKey);

        // Convert the decrypted key bytes to a SecretKey instance
        return new SecretKeySpec(decryptedKey, "AES");
    }
}