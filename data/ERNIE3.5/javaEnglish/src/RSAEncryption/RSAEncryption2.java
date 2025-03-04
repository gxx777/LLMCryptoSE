import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import javax.crypto.Cipher;

import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class RSAEncryption2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAEncryption2() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public String encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        // Encrypt the symmetric key using the public key
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSymmetricKey = encryptCipher.doFinal(symmetricKey);

        // Base64 encode the encrypted symmetric key
        return Base64.getEncoder().encodeToString(encryptedSymmetricKey);
    }

    public byte[] decryptSymmetricKey(String encryptedSymmetricKey) throws Exception {
        // Base64 decode the encrypted symmetric key
        byte[] encryptedSymmetricKeyBytes = Base64.getDecoder().decode(encryptedSymmetricKey);

        // Decrypt the symmetric key using the private key
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return decryptCipher.doFinal(encryptedSymmetricKeyBytes);
    }

    public static void main(String[] args) {
        try {
            RSAEncryption2 rsaEncryption = new RSAEncryption2();

            // Generate a symmetric key (example: AES key)
            byte[] symmetricKey = "ThisIsASymmetricKey".getBytes();

            // Encrypt the symmetric key using RSA
            String encryptedSymmetricKey = rsaEncryption.encryptSymmetricKey(symmetricKey);
            System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);

            // Decrypt the symmetric key using RSA
            byte[] decryptedSymmetricKey = rsaEncryption.decryptSymmetricKey(encryptedSymmetricKey);
            System.out.println("Decrypted Symmetric Key: " + new String(decryptedSymmetricKey));

            // Save the encrypted symmetric key to a file
            try (FileOutputStream fos = new FileOutputStream("encrypted_symmetric_key.dat")) {
                ObjectOutputStream oos = new ObjectOutputStream(fos);
                oos.writeObject(encryptedSymmetricKey);
                oos.close();
            }

            // Load the encrypted symmetric key from the file and decrypt it
            try (FileInputStream fis = new FileInputStream("encrypted_symmetric_key.dat")) {
                ObjectInputStream ois = new ObjectInputStream(fis);
                String loadedEncryptedSymmetricKey = (String) ois.readObject();
                ois.close();

                byte[] loadedDecryptedSymmetricKey = rsaEncryption.decryptSymmetricKey(loadedEncryptedSymmetricKey);
                System.out.println("Loaded and Decrypted Symmetric Key: " + new String(loadedDecryptedSymmetricKey));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}