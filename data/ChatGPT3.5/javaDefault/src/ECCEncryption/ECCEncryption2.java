import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.util.Base64;

public class ECCEncryption2 {

    private static final String ALGORITHM = "EC";
    private static final String SYMMETRIC_ALGORITHM = "AES";
    private static final int KEY_SIZE = 256;

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(KEY_SIZE);
        return keyGen.generateKeyPair();
    }

    public static byte[] encryptSymmetricKey(Key publicKey, SecretKey symmetricKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey.getEncoded());
    }

    public static SecretKey decryptSymmetricKey(Key privateKey, byte[] encryptedKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKey = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(decryptedKey, 0, decryptedKey.length, SYMMETRIC_ALGORITHM);
    }

    public static byte[] encryptData(SecretKey key, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] decryptData(SecretKey key, byte[] encryptedData) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

    public static void main(String[] args) {
        try {
            // Generate ECC key pair
            KeyPair keyPair = generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Generate symmetric key
            KeyGenerator keyGen = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
            keyGen.init(KEY_SIZE);
            SecretKey symmetricKey = keyGen.generateKey();

            // Encrypt symmetric key with public key
            byte[] encryptedKey = encryptSymmetricKey(publicKey, symmetricKey);

            // Decrypt symmetric key with private key
            SecretKey decryptedKey = decryptSymmetricKey(privateKey, encryptedKey);

            // Encrypt and decrypt data using symmetric key
            String plaintext = "Hello, World!";
            byte[] encryptedData = encryptData(decryptedKey, plaintext.getBytes());
            byte[] decryptedData = decryptData(decryptedKey, encryptedData);

            System.out.println("Original data: " + plaintext);
            System.out.println("Encrypted data: " + Base64.getEncoder().encodeToString(encryptedData));
            System.out.println("Decrypted data: " + new String(decryptedData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}