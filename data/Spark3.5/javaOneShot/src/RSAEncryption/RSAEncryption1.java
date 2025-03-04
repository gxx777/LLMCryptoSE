import javax.crypto.Cipher;
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

public class RSAEncryption1 {

    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;
    private static final String PADDING = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Encrypt the symmetric key file
        byte[] encryptedSymmetricKey = encryptSymmetricKey("path/to/symmetric_key_file", publicKey);
        Files.write(Paths.get("path/to/encrypted_symmetric_key_file"), encryptedSymmetricKey);

        // Decrypt the symmetric key file
        byte[] decryptedSymmetricKey = decryptSymmetricKey("path/to/encrypted_symmetric_key_file", privateKey);
        Files.write(Paths.get("path/to/decrypted_symmetric_key_file"), decryptedSymmetricKey);
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] encryptSymmetricKey(String filePath, PublicKey publicKey) throws Exception {
        byte[] symmetricKeyBytes = Files.readAllBytes(Paths.get(filePath));
        Cipher cipher = Cipher.getInstance(PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKeyBytes);
    }

    private static byte[] decryptSymmetricKey(String filePath, PrivateKey privateKey) throws Exception {
        byte[] encryptedSymmetricKeyBytes = Files.readAllBytes(Paths.get(filePath));
        Cipher cipher = Cipher.getInstance(PADDING);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKeyBytes);
    }
}