import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;

public class AsymmetricEncryption3 {

    private static final String ASYMMETRIC_ALGORITHM = "RSA";
    private static final String SYMMETRIC_ALGORITHM = "AES";

    // Generate RSA key pair
    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ASYMMETRIC_ALGORITHM);
        return keyPairGenerator.generateKeyPair();
    }

    // Encrypt symmetric key file using RSA public key
    public byte[] encryptKey(SecretKey symmetricKey, RSAPublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher encryptCipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return encryptCipher.doFinal(symmetricKey.getEncoded());
    }

    // Decrypt symmetric key file using RSA private key
    public SecretKey decryptKey(byte[] encryptedKey, RSAPrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher decryptCipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKey = decryptCipher.doFinal(encryptedKey);

        SecretKey secretKey = new javax.crypto.spec.SecretKeySpec(decryptedKey, 0, decryptedKey.length, SYMMETRIC_ALGORITHM);
        return secretKey;
    }

    public static void main(String[] args) {
        try {
            AsymmetricEncryption3 asymEncryptor = new AsymmetricEncryption3();

            // Generate RSA key pair
            KeyPair keyPair = asymEncryptor.generateKeyPair();

            // Generate symmetric key
            KeyGenerator keyGen = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
            keyGen.init(256);
            SecretKey symmetricKey = keyGen.generateKey();

            // Encrypt symmetric key file using RSA public key
            byte[] encryptedKey = asymEncryptor.encryptKey(symmetricKey, (RSAPublicKey)keyPair.getPublic());
            System.out.println("Encrypted Symmetric Key: " + new String(encryptedKey));

            // Decrypt symmetric key file using RSA private key
            SecretKey decryptedKey = asymEncryptor.decryptKey(encryptedKey, (RSAPrivateKey)keyPair.getPrivate());
            System.out.println("Decrypted Symmetric Key: " + decryptedKey.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}