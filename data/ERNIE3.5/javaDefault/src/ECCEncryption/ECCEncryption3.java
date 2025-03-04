import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ECCEncryption3 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ECCEncryption3() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("prime256v1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public byte[] encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey);
    }

    public byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }

    public static void main(String[] args) {
        try {
            ECCEncryption3 eccEncryption = new ECCEncryption3();

            // Generate a symmetric key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] symmetricKey = secretKey.getEncoded();

            // Encrypt the symmetric key using ECC
            byte[] encryptedSymmetricKey = eccEncryption.encryptSymmetricKey(symmetricKey);

            // Write the encrypted symmetric key to a file
            Files.write(Paths.get("encrypted_symmetric_key.bin"), encryptedSymmetricKey);

            // Read the encrypted symmetric key from the file
            byte[] readEncryptedSymmetricKey = Files.readAllBytes(Paths.get("encrypted_symmetric_key.bin"));

            // Decrypt the symmetric key using ECC
            byte[] decryptedSymmetricKey = eccEncryption.decryptSymmetricKey(readEncryptedSymmetricKey);

            // Verify that the decrypted symmetric key matches the original
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