import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.*;
import javax.crypto.spec.*;

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

    public byte[] encryptSymmetricKey(byte[] symmetricKey) throws CryptoException {
        try {
            Cipher cipher = Cipher.getInstance("ECIES");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(symmetricKey);
        } catch (Exception e) {
            throw new CryptoException("Encryption failed", e);
        }
    }

    public byte[] decryptSymmetricKey(byte[] encryptedKey) throws CryptoException {
        try {
            Cipher cipher = Cipher.getInstance("ECIES");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encryptedKey);
        } catch (Exception e) {
            throw new CryptoException("Decryption failed", e);
        }
    }

    public static void main(String[] args) {
        try {
            ECCEncryption1 eccEncryption = new ECCEncryption1();

            // Generate a symmetric key (for example, AES key)
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            SecretKey symmetricKey = keyGenerator.generateKey();
            byte[] symmetricKeyBytes = symmetricKey.getEncoded();

            // Encrypt the symmetric key
            byte[] encryptedSymmetricKey = eccEncryption.encryptSymmetricKey(symmetricKeyBytes);

            // Write the encrypted symmetric key to a file
            Files.write(Paths.get("encrypted_symmetric_key.bin"), encryptedSymmetricKey);

            // Read the encrypted symmetric key from the file
            byte[] readEncryptedSymmetricKey = Files.readAllBytes(Paths.get("encrypted_symmetric_key.bin"));

            // Decrypt the symmetric key
            byte[] decryptedSymmetricKey = eccEncryption.decryptSymmetricKey(readEncryptedSymmetricKey);

            // Verify that the decrypted symmetric key matches the original
            if (java.util.Arrays.equals(symmetricKeyBytes, decryptedSymmetricKey)) {
                System.out.println("Symmetric key decryption successful!");
            } else {
                System.out.println("Symmetric key decryption failed!");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Custom exception class for handling crypto-related exceptions
    static class CryptoException extends Exception {
        public CryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}