import java.io.*;
import java.security.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;

public class RSAEncryption1 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAEncryption1() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
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

    public static void main(String[] args) {
        try {
            RSAEncryption1 rsaEncryption = new RSAEncryption1();

            // Generate a symmetric key (e.g., AES)
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            SecretKey symmetricKey = keyGenerator.generateKey();

            // Encrypt the symmetric key with RSA
            byte[] encryptedSymmetricKey = rsaEncryption.encryptSymmetricKey(symmetricKey.getEncoded());

            // Decrypt the symmetric key with RSA
            byte[] decryptedSymmetricKey = rsaEncryption.decryptSymmetricKey(encryptedSymmetricKey);

            // Verify that the decrypted symmetric key matches the original
            if (Arrays.equals(symmetricKey.getEncoded(), decryptedSymmetricKey)) {
                System.out.println("Symmetric key encryption and decryption succeeded.");
            } else {
                System.out.println("Symmetric key decryption failed.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}