import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class ECCEncryption4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ECCEncryption4() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256); // ECC key size
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public byte[] encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        // Encrypt the symmetric key using the public key
        Cipher encryptCipher = Cipher.getInstance("ECIES");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return encryptCipher.doFinal(symmetricKey);
    }

    public byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey) throws Exception {
        // Decrypt the symmetric key using the private key
        Cipher decryptCipher = Cipher.getInstance("ECIES");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return decryptCipher.doFinal(encryptedSymmetricKey);
    }

    public static void main(String[] args) throws Exception {
        // Generate a symmetric key to encrypt
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey symmetricKey = keyGenerator.generateKey();

        // Convert the symmetric key to bytes
        byte[] symmetricKeyBytes = symmetricKey.getEncoded();

        // ECC Encryption for Symmetric Key
        ECCEncryption4 eccEncryption = new ECCEncryption4();

        // Encrypt the symmetric key with ECC
        byte[] encryptedSymmetricKey = eccEncryption.encryptSymmetricKey(symmetricKeyBytes);

        // Write the encrypted symmetric key to a file
        Path encryptedKeyPath = Paths.get("encryptedSymmetricKey.txt");
        Files.write(encryptedKeyPath, encryptedSymmetricKey);

        // Read the encrypted symmetric key from the file
        byte[] readEncryptedSymmetricKey = Files.readAllBytes(encryptedKeyPath);

        // Decrypt the symmetric key with ECC
        byte[] decryptedSymmetricKey = eccEncryption.decryptSymmetricKey(readEncryptedSymmetricKey);

        // Convert the decrypted symmetric key back to a SecretKey
        SecretKey decryptedSymmetricKeyObj = new SecretKeySpec(decryptedSymmetricKey, "AES");

        // Verify that the decrypted symmetric key is the same as the original
        System.out.println("Symmetric Keys are the same: " + Arrays.equals(symmetricKey.getEncoded(), decryptedSymmetricKeyObj.getEncoded()));
    }
}