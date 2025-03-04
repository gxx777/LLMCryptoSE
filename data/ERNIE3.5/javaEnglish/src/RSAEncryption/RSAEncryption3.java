import java.io.*;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;

public class RSAEncryption3 {

    public static void main(String[] args) throws Exception {
        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Symmetric key to be encrypted and decrypted
        SecretKey symmetricKey = KeyGenerator.getInstance("AES").generateKey();

        // Encrypt the symmetric key using RSA public key
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSymmetricKey = encryptCipher.doFinal(symmetricKey.getEncoded());
        String encryptedSymmetricKeyBase64 = Base64.getEncoder().encodeToString(encryptedSymmetricKey);
        System.out.println("Encrypted Symmetric Key (Base64): " + encryptedSymmetricKeyBase64);

        // Decrypt the symmetric key using RSA private key
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSymmetricKey = decryptCipher.doFinal(Base64.getDecoder().decode(encryptedSymmetricKeyBase64));
        SecretKey decryptedSymmetricKeyObj = new SecretKeySpec(decryptedSymmetricKey, "AES");
        System.out.println("Decrypted Symmetric Key: " + Arrays.toString(decryptedSymmetricKeyObj.getEncoded()));
    }
}