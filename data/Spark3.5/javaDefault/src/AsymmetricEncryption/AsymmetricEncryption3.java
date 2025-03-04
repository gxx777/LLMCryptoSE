import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

public class AsymmetricEncryption3 {
    private static final String RSA = "RSA";
    private static final String AES = "AES";
    private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final int KEY_SIZE = 2048;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPair keyPair = generateKeyPair();

        // Encrypt the symmetric key file
        byte[] encryptedSymmetricKey = encryptSymmetricKey(keyPair.getPublic(), "symmetric_key.txt");
        Files.write(Paths.get("encrypted_symmetric_key.txt"), encryptedSymmetricKey);

        // Decrypt the symmetric key file
        byte[] decryptedSymmetricKey = decryptSymmetricKey(keyPair.getPrivate(), encryptedSymmetricKey);
        Files.write(Paths.get("decrypted_symmetric_key.txt"), decryptedSymmetricKey);
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA, "BC");
        keyPairGenerator.initialize(KEY_SIZE, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] encryptSymmetricKey(PublicKey publicKey, String symmetricKeyFilePath) throws Exception {
        byte[] symmetricKey = Files.readAllBytes(Paths.get(symmetricKeyFilePath));
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey);
    }

    private static byte[] decryptSymmetricKey(PrivateKey privateKey, byte[] encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }
}