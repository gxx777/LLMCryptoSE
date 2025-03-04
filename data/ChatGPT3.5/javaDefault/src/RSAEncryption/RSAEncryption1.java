import javax.crypto.Cipher;
import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSAEncryption1 {

    private static final String ALGORITHM = "RSA";
    private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final int KEY_SIZE = 2048;

    public static void main(String[] args) {
        try {
            // Generate RSA key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(KEY_SIZE);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Encrypt symmetric key file using public key
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            File symmetricKeyFile = new File("symmetric.key");
            FileInputStream fis = new FileInputStream(symmetricKeyFile);
            byte[] inputBytes = new byte[(int) symmetricKeyFile.length()];
            fis.read(inputBytes);
            byte[] encryptedBytes = cipher.doFinal(inputBytes);

            File encryptedSymmetricKeyFile = new File("encrypted_symmetric.key");
            FileOutputStream fos = new FileOutputStream(encryptedSymmetricKeyFile);
            fos.write(encryptedBytes);

            // Decrypt symmetric key file using private key
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            fis = new FileInputStream(encryptedSymmetricKeyFile);
            inputBytes = new byte[(int) encryptedSymmetricKeyFile.length()];
            fis.read(inputBytes);
            byte[] decryptedBytes = cipher.doFinal(inputBytes);

            File decryptedSymmetricKeyFile = new File("decrypted_symmetric.key");
            fos = new FileOutputStream(decryptedSymmetricKeyFile);
            fos.write(decryptedBytes);

            System.out.println("Symmetric key encryption and decryption using RSA completed successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}