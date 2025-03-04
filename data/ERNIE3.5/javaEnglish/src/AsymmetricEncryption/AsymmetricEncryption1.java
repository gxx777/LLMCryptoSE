import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AsymmetricEncryption1 {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public AsymmetricEncryption1() throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public byte[] encryptSymmetricKey(byte[] symmetricKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
        // Encrypt the symmetric key using the public key
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey);
    }

    public byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // Decrypt the symmetric key using the private key
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }

    public static void main(String[] args) {
        try {
            // Create an instance of AsymmetricEncryption1
            AsymmetricEncryption1 encryption = new AsymmetricEncryption1();

            // Generate a symmetric key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            SecretKey symmetricKey = keyGenerator.generateKey();

            // Encrypt the symmetric key
            byte[] encryptedSymmetricKey = encryption.encryptSymmetricKey(symmetricKey.getEncoded());

            // Convert the encrypted key to Base64 string
            String encryptedSymmetricKeyString = Base64.getEncoder().encodeToString(encryptedSymmetricKey);
            System.out.println("Encrypted Symmetric Key (Base64): " + encryptedSymmetricKeyString);

            // Decrypt the symmetric key
            byte[] decryptedSymmetricKey = encryption.decryptSymmetricKey(Base64.getDecoder().decode(encryptedSymmetricKeyString));

            // Convert the decrypted key back to SecretKey
            SecretKey decryptedSymmetricKeyObj = new SecretKeySpec(decryptedSymmetricKey, "AES");
            System.out.println("Decrypted Symmetric Key: " + decryptedSymmetricKeyObj);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}