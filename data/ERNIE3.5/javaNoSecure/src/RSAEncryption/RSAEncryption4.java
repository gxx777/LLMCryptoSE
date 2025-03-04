import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;

public class RSAEncryption4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAEncryption4() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public byte[] encryptSymmetricKey(SecretKey symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey.getEncoded());
    }

    public SecretKey decryptSymmetricKey(byte[] encryptedKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedKey = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(decodedKey, "AES"); // Assuming AES symmetric key
    }

    public void saveSymmetricKey(SecretKey symmetricKey, String filePath) throws Exception {
        byte[] encryptedKey = encryptSymmetricKey(symmetricKey);
        try (FileOutputStream fos = new FileOutputStream(filePath);
             ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(encryptedKey);
        }
    }

    public SecretKey loadSymmetricKey(String filePath) throws Exception {
        try (FileInputStream fis = new FileInputStream(filePath);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            byte[] encryptedKey = (byte[]) ois.readObject();
            return decryptSymmetricKey(encryptedKey);
        }
    }

    public static void main(String[] args) throws Exception {
        RSAEncryption4 rsaEncryption = new RSAEncryption4();

        // Generate a symmetric key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey symmetricKey = keyGenerator.generateKey();

        // Save the symmetric key encrypted with RSA
        rsaEncryption.saveSymmetricKey(symmetricKey, "symmetric_key.enc");

        // Load and decrypt the symmetric key
        SecretKey loadedKey = rsaEncryption.loadSymmetricKey("symmetric_key.enc");

        // Verify that the loaded key is the same as the original
        System.out.println(loadedKey.getEncoded().length == symmetricKey.getEncoded().length);
    }
}