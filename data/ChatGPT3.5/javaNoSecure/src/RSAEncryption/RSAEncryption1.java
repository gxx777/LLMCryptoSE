import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.io.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class RSAEncryption1 {

    private static final String PUBLIC_KEY_FILE = "public_key.txt";
    private static final String PRIVATE_KEY_FILE = "private_key.txt";
    private static final String SYMMETRIC_KEY_FILE = "symmetric_key.txt";

    public static void main(String[] args) {
        try {
            // Generate RSA key pair
            KeyPair keyPair = generateRSAKeyPair();

            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Save public and private key to files
            saveKeyToFile(publicKey, PUBLIC_KEY_FILE);
            saveKeyToFile(privateKey, PRIVATE_KEY_FILE);

            // Generate symmetric key
            Key symmetricKey = generateSymmetricKey();

            // Encrypt symmetric key with RSA public key
            byte[] encryptedSymmetricKey = encryptKey(symmetricKey.getEncoded(), publicKey);

            // Save encrypted symmetric key to file
            saveKeyToFile(encryptedSymmetricKey, SYMMETRIC_KEY_FILE);

            // Decrypt symmetric key with RSA private key
            byte[] decryptedSymmetricKey = decryptKey(encryptedSymmetricKey, privateKey);

            // Use symmetric key for encryption and decryption of data
            // Example:
            // byte[] encryptedData = encryptData(data, new SecretKeySpec(decryptedSymmetricKey, "AES"));
            // byte[] decryptedData = decryptData(encryptedData, new SecretKeySpec(decryptedSymmetricKey, "AES"));
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static void saveKeyToFile(Key key, String fileName) throws IOException {
        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(fileName))) {
            out.writeObject(key);
        }
    }

    private static void saveKeyToFile(byte[] keyBytes, String fileName) throws IOException {
        try (BufferedOutputStream out =
                     new BufferedOutputStream(new FileOutputStream(fileName))) {
            out.write(keyBytes);
        }
    }

    private static Key generateSymmetricKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    private static byte[] encryptKey(byte[] key, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(key);
    }

    private static byte[] decryptKey(byte[] encryptedKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedKey);
    }

    // Add methods for encrypting and decrypting data using symmetric key here
}