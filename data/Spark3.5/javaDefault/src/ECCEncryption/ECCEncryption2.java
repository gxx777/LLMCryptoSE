import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

public class ECCEncryption2 {
    private static final String ALGORITHM = "EC";
    private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    public static void main(String[] args) throws Exception {
        // Generate ECC key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Encrypt the symmetric key
        String symmetricKey = "ThisIsASymmetricKey";
        System.out.println("Original Symmetric Key: " + symmetricKey);
        byte[] encryptedSymmetricKey = encrypt(symmetricKey, publicKey);
        System.out.println("Encrypted Symmetric Key: " + Base64.getEncoder().encodeToString(encryptedSymmetricKey));

        // Decrypt the symmetric key
        String decryptedSymmetricKey = decrypt(encryptedSymmetricKey, privateKey);
        System.out.println("Decrypted Symmetric Key: " + decryptedSymmetricKey);
    }

    public static byte[] encrypt(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes());
    }

    public static String decrypt(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedData = cipher.doFinal(data);
        return new String(decryptedData);
    }
}