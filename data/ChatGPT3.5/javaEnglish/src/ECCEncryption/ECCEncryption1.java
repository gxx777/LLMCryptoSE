import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class ECCEncryption1 {

    public static void main(String[] args) throws Exception {
        // Generate ECC key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecSpec);
        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Generate symmetric key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256); // Choose the key size as needed
        SecretKey secretKey = keyGenerator.generateKey();

        // Encrypt symmetric key
        Cipher cipher = Cipher.getInstance("ECIES", "BC"); // Use BC provider for ECC encryption
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(secretKey.getEncoded());

        // Save encrypted key to file
        try (FileOutputStream fos = new FileOutputStream("encryptedKeyFile")) {
            fos.write(encryptedKey);
        }

        // Read encrypted key from file
        byte[] encryptedKeyBytes;
//        try (FileInputStream fis = new FileInputStream("encryptedKeyFile")) {
//            encryptedKeyBytes = fis.readAllBytes();
//        }
        encryptedKeyBytes = Files.readAllBytes(Paths.get("encryptedKeyFile"));


        // Decrypt symmetric key
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKey = cipher.doFinal(encryptedKeyBytes);

        // Use decrypted key for encryption and decryption of data
        SecretKey decryptedSecretKey = new SecretKeySpec(decryptedKey, "AES");

        // Perform encryption and decryption operations as needed with decryptedSecretKey
    }
}