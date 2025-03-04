import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ECCEncryption4 {
    private static final String ALGORITHM = "EC";
    private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final int KEY_SIZE = 256;

    public static void main(String[] args) throws Exception {
        // Generate ECC key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Encrypt the symmetric key
        byte[] symmetricKey = generateSymmetricKey();
        byte[] encryptedSymmetricKey = encryptSymmetricKey(keyPair.getPublic(), symmetricKey);

        // Decrypt the symmetric key
        byte[] decryptedSymmetricKey = decryptSymmetricKey(keyPair.getPrivate(), encryptedSymmetricKey);

        // Check if the decrypted symmetric key is equal to the original one
        if (MessageDigest.isEqual(symmetricKey, decryptedSymmetricKey)) {
            System.out.println("Symmetric key encryption and decryption using ECC are successful.");
        } else {
            System.out.println("Symmetric key encryption and decryption using ECC failed.");
        }
    }

    private static byte[] generateSymmetricKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey.getEncoded();
    }

    private static byte[] encryptSymmetricKey(PublicKey publicKey, byte[] symmetricKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey);
    }

    private static byte[] decryptSymmetricKey(PrivateKey privateKey, byte[] encryptedSymmetricKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }
}