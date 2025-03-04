import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class RSAEncryption1 {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAEncryption1() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public String encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(symmetricKey);
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    public byte[] decryptSymmetricKey(String encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encryptedKeyBytes = Base64.getDecoder().decode(encryptedSymmetricKey);
        return cipher.doFinal(encryptedKeyBytes);
    }

    public static void main(String[] args) throws Exception {
        RSAEncryption1 rsaEncryption = new RSAEncryption1();

        // Generate a symmetric key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey symmetricKey = keyGenerator.generateKey();
        byte[] symmetricKeyBytes = symmetricKey.getEncoded();

        // Encrypt the symmetric key
        String encryptedSymmetricKey = rsaEncryption.encryptSymmetricKey(symmetricKeyBytes);
        System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);

        // Decrypt the symmetric key
        byte[] decryptedSymmetricKeyBytes = rsaEncryption.decryptSymmetricKey(encryptedSymmetricKey);
        SecretKey decryptedSymmetricKey = new SecretKeySpec(decryptedSymmetricKeyBytes, "AES");
        System.out.println("Decrypted Symmetric Key: " + Arrays.toString(decryptedSymmetricKey.getEncoded()));
    }
}