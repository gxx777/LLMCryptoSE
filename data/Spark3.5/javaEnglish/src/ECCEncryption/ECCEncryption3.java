import java.security.*;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ECCEncryption3 {

    public static void main(String[] args) throws Exception {
        // Generate ECC key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = kpg.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Encrypt the symmetric key using ECC public key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSymmetricKey = cipher.doFinal(secretKey.getEncoded());

        // Decrypt the symmetric key using ECC private key
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSymmetricKey = cipher.doFinal(encryptedSymmetricKey);
        SecretKey decryptedSecretKey = new SecretKeySpec(decryptedSymmetricKey, "AES");

        // Encrypt and decrypt a message using the symmetric key
        String message = "Hello, World!";
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, decryptedSecretKey, ivParameterSpec);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, decryptedSecretKey, ivParameterSpec);
        byte[] decryptedMessage = cipher.doFinal(encryptedMessage);
        System.out.println("Decrypted message: " + new String(decryptedMessage));
    }
}