import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AsymmetricEncryption2 {

    private static final String SYMMETRIC_KEY_FILE = "symmetric_key.txt";
    private static final String PUBLIC_KEY_FILE = "public_key.txt";
    private static final String PRIVATE_KEY_FILE = "private_key.txt";
    private static final String ENCRYPTED_SYMMETRIC_KEY_FILE = "encrypted_symmetric_key.txt";

    public static void main(String[] args) throws Exception {
        // Generate a symmetric key
        SecretKey symmetricKey = generateSymmetricKey();

        // Save the symmetric key to a file
        saveKeyToFile(symmetricKey, SYMMETRIC_KEY_FILE);

        // Generate a public/private key pair
        KeyPair keyPair = generateKeyPair();

        // Save the public key to a file
        saveKeyToFile(keyPair.getPublic(), PUBLIC_KEY_FILE);

        // Save the private key to a file
        saveKeyToFile(keyPair.getPrivate(), PRIVATE_KEY_FILE);

        // Encrypt the symmetric key using the public key
        byte[] encryptedSymmetricKey = encryptSymmetricKey(symmetricKey, keyPair.getPublic());

        // Save the encrypted symmetric key to a file
        saveEncryptedKeyToFile(encryptedSymmetricKey, ENCRYPTED_SYMMETRIC_KEY_FILE);

        // Decrypt the symmetric key using the private key
        SecretKey decryptedSymmetricKey = decryptSymmetricKey(encryptedSymmetricKey, keyPair.getPrivate());

        // Check if the decrypted symmetric key matches the original one
        System.out.println("Decrypted symmetric key matches original: " + symmetricKey.equals(decryptedSymmetricKey));
    }

    private static SecretKey generateSymmetricKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("RC4");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static void saveKeyToFile(Object key, String fileName) throws Exception {
        byte[] keyBytes = key instanceof PublicKey ? ((PublicKey) key).getEncoded() : ((PrivateKey) key).getEncoded();
        String base64Key = Base64.getEncoder().encodeToString(keyBytes);
        Files.write(Paths.get(fileName), base64Key.getBytes());
    }

    private static byte[] loadKeyFromFile(String fileName) throws Exception {
        String base64Key = new String(Files.readAllBytes(Paths.get(fileName)));
        return Base64.getDecoder().decode(base64Key);
    }

    private static void saveEncryptedKeyToFile(byte[] encryptedKey, String fileName) throws Exception {
        Files.write(Paths.get(fileName), encryptedKey);
    }

    private static byte[] encryptSymmetricKey(SecretKey symmetricKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey.getEncoded());
    }

    private static SecretKey decryptSymmetricKey(byte[] encryptedKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedKey);
        return new javax.crypto.spec.SecretKeySpec(decryptedKeyBytes, "RC4");
    }
}