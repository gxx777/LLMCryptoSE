import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;

public class ECCEncryption3 {

    private static final String ALGORITHM = "EC";
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(256);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] encrypt(Key key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(Key key, byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

    public static byte[] sign(PrivateKey privateKey, byte[] data) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verify(PublicKey publicKey, byte[] data, byte[] signature) throws Exception {
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    public static void saveKeyToFile(Key key, String fileName) throws Exception {
        byte[] keyBytes = key.getEncoded();
        FileOutputStream fos = new FileOutputStream(fileName);
        fos.write(keyBytes);
        fos.close();
    }

    public static Key getKeyFromFile(String fileName, String algorithm) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(fileName));
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
    }
    // Method to generate a symmetric key
    public static Key generateSymmetricKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    public static void main(String[] args) {
        try {
            // Generate ECC key pair
            KeyPair keyPair = generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // Save keys to file
            saveKeyToFile(privateKey, "privateKey.pem");
            saveKeyToFile(publicKey, "publicKey.pem");

            // Encrypt and decrypt a symmetric key file
            Key symmetricKey = generateSymmetricKey(); // Assuming this method generates a symmetric key
            byte[] encryptedKey = encrypt(publicKey, symmetricKey.getEncoded());
            byte[] decryptedKey = decrypt(privateKey, encryptedKey);

            // Sign and verify a message
            byte[] message = "Hello, ECC Encryption!".getBytes();
            byte[] signature = sign(privateKey, message);
            boolean isVerified = verify(publicKey, message, signature);

            System.out.println("Encryption and decryption successful!");
            System.out.println("Message verified: " + isVerified);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}