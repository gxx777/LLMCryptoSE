import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;

public class ECCEncryption2 {

    private static final String ALGORITHM = "EC";
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final String PUBLIC_KEY_FILE = "publicKeyFile.pub";
    private static final String PRIVATE_KEY_FILE = "privateKeyFile.priv";
    private static final String SYMMETRIC_KEY_FILE = "symmetricKeyFile.bin";

    public static void generateKeys() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(256);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            ObjectOutputStream publicKeyOS = new ObjectOutputStream(new FileOutputStream(PUBLIC_KEY_FILE));
            publicKeyOS.writeObject(publicKey);
            publicKeyOS.close();

            ObjectOutputStream privateKeyOS = new ObjectOutputStream(new FileOutputStream(PRIVATE_KEY_FILE));
            privateKeyOS.writeObject(privateKey);
            privateKeyOS.close();
            
            System.out.println("Public and private keys generated successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void encryptSymmetricKey(byte[] symmetricKey) {
        try {
            ObjectInputStream publicKeyIS = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
            PublicKey publicKey = (PublicKey) publicKeyIS.readObject();
            publicKeyIS.close();

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedSymmetricKey = cipher.doFinal(symmetricKey);

            FileOutputStream outputStream = new FileOutputStream(SYMMETRIC_KEY_FILE);
            outputStream.write(encryptedSymmetricKey);
            outputStream.close();

            System.out.println("Symmetric key encrypted successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] decryptSymmetricKey() {
        try {
            ObjectInputStream privateKeyIS = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
            PrivateKey privateKey = (PrivateKey) privateKeyIS.readObject();
            privateKeyIS.close();

            byte[] encryptedSymmetricKey = Files.readAllBytes(Paths.get(SYMMETRIC_KEY_FILE));

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedSymmetricKey = cipher.doFinal(encryptedSymmetricKey);
            
            System.out.println("Symmetric key decrypted successfully.");
            return decryptedSymmetricKey;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        generateKeys();
        
        // Generate a random symmetric key for encryption
        SecureRandom random = new SecureRandom();
        byte[] symmetricKey = new byte[16];
        random.nextBytes(symmetricKey);

        encryptSymmetricKey(symmetricKey);

        byte[] decryptedSymmetricKey = decryptSymmetricKey();

        // Use the decrypted symmetric key for further encryption/decryption operations
    }
}