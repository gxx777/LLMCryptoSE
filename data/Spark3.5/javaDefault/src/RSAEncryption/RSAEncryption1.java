import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAEncryption1 {

    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;
    private static final String PRIVATE_KEY_FILE = "private_key.der";
    private static final String PUBLIC_KEY_FILE = "public_key.der";
    private static final String SYMMETRIC_KEY_FILE = "symmetric_key.txt";
    private static final String ENCRYPTED_SYMMETRIC_KEY_FILE = "encrypted_symmetric_key.txt";
    private static final String DECRYPTED_SYMMETRIC_KEY_FILE = "decrypted_symmetric_key.txt";

    public static void main(String[] args) throws Exception {
        // Generate key pair
        generateKeyPair();

        // Encrypt symmetric key
        encryptSymmetricKey();

        // Decrypt symmetric key
        decryptSymmetricKey();
    }

    private static void generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Save private key to file
        byte[] privateKeyBytes = privateKey.getEncoded();
        Files.write(Paths.get(PRIVATE_KEY_FILE), privateKeyBytes);

        // Save public key to file
        byte[] publicKeyBytes = publicKey.getEncoded();
        Files.write(Paths.get(PUBLIC_KEY_FILE), publicKeyBytes);
    }

    private static void encryptSymmetricKey() throws Exception {
        // Read symmetric key from file
        byte[] symmetricKeyBytes = Files.readAllBytes(Paths.get(SYMMETRIC_KEY_FILE));

        // Read public key from file
        byte[] publicKeyBytes = Files.readAllBytes(Paths.get(PUBLIC_KEY_FILE));
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        // Encrypt symmetric key using public key
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSymmetricKeyBytes = cipher.doFinal(symmetricKeyBytes);

        // Save encrypted symmetric key to file
        Files.write(Paths.get(ENCRYPTED_SYMMETRIC_KEY_FILE), encryptedSymmetricKeyBytes);
    }

    private static void decryptSymmetricKey() throws Exception {
        // Read encrypted symmetric key from file
        byte[] encryptedSymmetricKeyBytes = Files.readAllBytes(Paths.get(ENCRYPTED_SYMMETRIC_KEY_FILE));

        // Read private key from file
        byte[] privateKeyBytes = Files.readAllBytes(Paths.get(PRIVATE_KEY_FILE));
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        // Decrypt symmetric key using private key
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSymmetricKeyBytes = cipher.doFinal(encryptedSymmetricKeyBytes);

        // Save decrypted symmetric key to file
        Files.write(Paths.get(DECRYPTED_SYMMETRIC_KEY_FILE), decryptedSymmetricKeyBytes);
    }
}