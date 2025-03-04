import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class AsymmetricEncryption2 {

    public static void main(String[] args) {
        try {
            // Generate a symmetric key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey symmetricKey = keyGen.generateKey();

            // Initialize the asymmetric keypair
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = new SecureRandom();
            keyPairGen.initialize(2048, random);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            // Encrypt the symmetric key using the public key
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] encryptedKey = cipher.doFinal(symmetricKey.getEncoded());

            System.out.println("Symmetric key encrypted successfully");

            // Decrypt the symmetric key using the private key
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] decryptedKey = cipher.doFinal(encryptedKey);

            System.out.println("Symmetric key decrypted successfully");

            // Compare the original symmetric key with the decrypted key
            SecretKey decryptedSymmetricKey = new SecretKeySpec(decryptedKey, symmetricKey.getAlgorithm());
            if (symmetricKey.equals(decryptedSymmetricKey)) {
                System.out.println("Original symmetric key matches the decrypted key");
            } else {
                System.out.println("Original symmetric key does not match the decrypted key");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}