import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class AsymmetricEncryption1 {

    private static final String PUBLIC_KEY_FILE = "public_key.der";
    private static final String PRIVATE_KEY_FILE = "private_key.der";
    private static final String SYMMETRIC_KEY_FILE = "symmetric_key.txt";
    private static final String ENCRYPTED_SYMMETRIC_KEY_FILE = "encrypted_symmetric_key.txt";
    private static final String DECRYPTED_SYMMETRIC_KEY_FILE = "decrypted_symmetric_key.txt";

    public static void main(String[] args) throws Exception {
        // Generate or load public and private keys
        PublicKey publicKey = loadPublicKey();
        PrivateKey privateKey = loadPrivateKey();

        // Encrypt the symmetric key file
        encryptSymmetricKeyFile(publicKey);

        // Decrypt the encrypted symmetric key file
        decryptSymmetricKeyFile(privateKey);
    }

    private static PublicKey loadPublicKey() throws Exception {
        byte[] publicKeyBytes = Files.readAllBytes(Paths.get(PUBLIC_KEY_FILE));
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    private static PrivateKey loadPrivateKey() throws Exception {
        byte[] privateKeyBytes = Files.readAllBytes(Paths.get(PRIVATE_KEY_FILE));
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    private static void encryptSymmetricKeyFile(PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] symmetricKeyBytes = Files.readAllBytes(Paths.get(SYMMETRIC_KEY_FILE));
        byte[] encryptedSymmetricKeyBytes = cipher.doFinal(symmetricKeyBytes);

        try (FileOutputStream fos = new FileOutputStream(ENCRYPTED_SYMMETRIC_KEY_FILE)) {
            fos.write(encryptedSymmetricKeyBytes);
        }
    }

    private static void decryptSymmetricKeyFile(PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] encryptedSymmetricKeyBytes = Files.readAllBytes(Paths.get(ENCRYPTED_SYMMETRIC_KEY_FILE));
        byte[] decryptedSymmetricKeyBytes = cipher.doFinal(encryptedSymmetricKeyBytes);

        try (FileOutputStream fos = new FileOutputStream(DECRYPTED_SYMMETRIC_KEY_FILE)) {
            fos.write(decryptedSymmetricKeyBytes);
        }
    }
}