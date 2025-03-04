import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AsymmetricEncryption4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public AsymmetricEncryption4() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
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
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(decryptedKeyBytes, "AES");
    }

    public void encryptSymmetricKeyFile(SecretKey symmetricKey, File inputFile, File outputFile) throws Exception {
        byte[] encryptedSymmetricKey = encryptSymmetricKey(symmetricKey);
        try (FileOutputStream fos = new FileOutputStream(outputFile);
             CipherOutputStream cos = new CipherOutputStream(fos, Cipher.getInstance("RSA"))) {
            cos.write(encryptedSymmetricKey);
        }
    }

    public SecretKey decryptSymmetricKeyFile(File encryptedKeyFile, File outputFile) throws Exception {
        byte[] encryptedSymmetricKey = new byte[(int) encryptedKeyFile.length()];
        try (FileInputStream fis = new FileInputStream(encryptedKeyFile);
             CipherInputStream cis = new CipherInputStream(fis, Cipher.getInstance("RSA"))) {
            cis.read(encryptedSymmetricKey);
        }
        return decryptSymmetricKey(encryptedSymmetricKey);
    }

    public static void main(String[] args) throws Exception {
        // Create an instance of AsymmetricEncryption4
        AsymmetricEncryption4 aes4 = new AsymmetricEncryption4();

        // Generate a symmetric key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey symmetricKey = keyGenerator.generateKey();

        // Encrypt the symmetric key using AsymmetricEncryption4
        byte[] encryptedSymmetricKey = aes4.encryptSymmetricKey(symmetricKey);

        // Write the encrypted symmetric key to a file
        File encryptedKeyFile = new File("encrypted_symmetric_key.bin");
        aes4.encryptSymmetricKeyFile(symmetricKey, new File("dummy_input.txt"), encryptedKeyFile);

        // Read the encrypted symmetric key from the file and decrypt it
        SecretKey decryptedSymmetricKey = aes4.decryptSymmetricKeyFile(encryptedKeyFile, new File("decrypted_dummy_output.txt"));

        // Test if the decrypted symmetric key is the same as the original one
        System.out.println("Original and decrypted symmetric keys are the same: " + symmetricKey.getEncoded().equals(decryptedSymmetricKey.getEncoded()));
    }
}