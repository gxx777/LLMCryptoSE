import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;

public class AsymmetricEncryption2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public AsymmetricEncryption2() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public byte[] encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey);
    }

    public byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }

    public void savePrivateKey(String filePath) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(filePath);
             ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(privateKey);
        }
    }

    public PrivateKey loadPrivateKey(String filePath) throws Exception {
        try (FileInputStream fis = new FileInputStream(filePath);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            return (PrivateKey) ois.readObject();
        }
    }

    public static void main(String[] args) {
        try {
            // Generate a new instance of AsymmetricEncryption2
            AsymmetricEncryption2 encryption = new AsymmetricEncryption2();

            // Generate a symmetric key (for example, AES key)
            byte[] symmetricKey = "mySymmetricKey".getBytes();

            // Encrypt the symmetric key using RSA public key
            byte[] encryptedSymmetricKey = encryption.encryptSymmetricKey(symmetricKey);

            // Save the private key for decryption later
            encryption.savePrivateKey("private_key.ser");

            // Load the private key from file
            PrivateKey privateKey = encryption.loadPrivateKey("private_key.ser");

            // Decrypt the symmetric key using RSA private key
            byte[] decryptedSymmetricKey = encryption.decryptSymmetricKey(encryptedSymmetricKey);

            // Verify that the decrypted symmetric key matches the original key
            if (java.util.Arrays.equals(symmetricKey, decryptedSymmetricKey)) {
                System.out.println("Symmetric key decryption successful!");
            } else {
                System.out.println("Symmetric key decryption failed!");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}