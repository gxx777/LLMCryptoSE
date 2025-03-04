import java.security.*;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class ECCEncryption4 {

    private static final String EC_ALGORITHM = "EC";
    private static final String SYMMETRIC_ALGORITHM = "AES";

    public static void main(String[] args) throws Exception {
        // Generate ECC key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(EC_ALGORITHM);
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Generate symmetric key
        KeyGenerator keyGenerator = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
        keyGenerator.init(256);
        SecretKey symmetricKey = keyGenerator.generateKey();

        // Encrypt symmetric key using ECC public key
        Cipher cipher = Cipher.getInstance(EC_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encryptedSymmetricKey = cipher.doFinal(symmetricKey.getEncoded());

        // Decrypt symmetric key using ECC private key
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decryptedSymmetricKey = cipher.doFinal(encryptedSymmetricKey);

        // Verify that decrypted symmetric key matches original symmetric key
        boolean symmetricKeyMatch = MessageDigest.isEqual(symmetricKey.getEncoded(), decryptedSymmetricKey);

        if (symmetricKeyMatch) {
            System.out.println("Symmetric key encryption and decryption successful.");
        } else {
            System.out.println("Symmetric key encryption and decryption failed.");
        }
    }
}