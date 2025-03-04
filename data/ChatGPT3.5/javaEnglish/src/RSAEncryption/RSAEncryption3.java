import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

public class RSAEncryption3 {

    public static String encryptSymmetricKey(byte[] symmetricKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(symmetricKey);
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    public static byte[] decryptSymmetricKey(String encryptedKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKey = cipher.doFinal(Base64.getDecoder().decode(encryptedKey));
        return decryptedKey;
    }

    public static void main(String[] args) throws Exception {
        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Generate symmetric key (for demonstration purposes, you can replace this with your own key generation logic)
        byte[] symmetricKey = "ThisIsASecretKey".getBytes();

        // Encrypt symmetric key using public key
        String encryptedKey = encryptSymmetricKey(symmetricKey, keyPair.getPublic());
        System.out.println("Encrypted Symmetric Key: " + encryptedKey);

        // Decrypt symmetric key using private key
        byte[] decryptedKey = decryptSymmetricKey(encryptedKey, keyPair.getPrivate());
        System.out.println("Decrypted Symmetric Key: " + new String(decryptedKey));
    }
}