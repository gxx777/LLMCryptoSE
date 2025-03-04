import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ECCEncryption1 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ECCEncryption1() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("prime256v1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public String encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSymmetricKey = cipher.doFinal(symmetricKey);
        return Base64.getEncoder().encodeToString(encryptedSymmetricKey);
    }

    public byte[] decryptSymmetricKey(String encryptedSymmetricKey) throws Exception {
        byte[] encryptedSymmetricKeyBytes = Base64.getDecoder().decode(encryptedSymmetricKey);
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKeyBytes);
    }

    public static void main(String[] args) {
        try {
            ECCEncryption1 eccEncryption = new ECCEncryption1();

            // Generate a symmetric key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] symmetricKey = secretKey.getEncoded();

            // Encrypt the symmetric key
            String encryptedSymmetricKey = eccEncryption.encryptSymmetricKey(symmetricKey);
            System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);

            // Decrypt the symmetric key
            byte[] decryptedSymmetricKey = eccEncryption.decryptSymmetricKey(encryptedSymmetricKey);
            System.out.println("Decrypted Symmetric Key: " + new String(decryptedSymmetricKey));

            // Save and Load the encrypted symmetric key to/from a file
            FileOutputStream fos = new FileOutputStream("encrypted_symmetric_key.txt");
            fos.write(encryptedSymmetricKey.getBytes());
            fos.close();

            FileInputStream fis = new FileInputStream("encrypted_symmetric_key.txt");
            byte[] buffer = new byte[fis.available()];
            fis.read(buffer);
            fis.close();

            String loadedEncryptedSymmetricKey = new String(buffer);
            byte[] loadedDecryptedSymmetricKey = eccEncryption.decryptSymmetricKey(loadedEncryptedSymmetricKey);
            System.out.println("Loaded and Decrypted Symmetric Key: " + new String(loadedDecryptedSymmetricKey));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}